-- Supabase > SQL Editor > New query > tempel semua > Run
-- Tidak butuh Auth sama sekali. Semua akses lewat fungsi (RPC); tabel dikunci.

create table public.boxes (
  id bigint generated always as identity primary key,
  username text unique not null check (username ~ '^[a-z0-9_]{3,20}$'),
  key_hash text not null,                       -- hash kunci rahasia pemilik
  created_at timestamptz not null default now()
);

create table public.messages (
  id bigint generated always as identity primary key,
  box_id bigint not null references public.boxes(id) on delete cascade,
  sender_hash text not null,                    -- hash token anonim pengirim (tidak pernah dikirim balik)
  body text not null check (char_length(body) between 1 and 500),
  reply text check (reply is null or char_length(reply) between 1 and 500),
  replied_at timestamptz,
  created_at timestamptz not null default now()
);
create index messages_box_idx on public.messages (box_id, created_at desc);

-- RLS aktif tanpa policy = tabel tidak bisa disentuh langsung dari browser
alter table public.boxes enable row level security;
alter table public.messages enable row level security;

-- ---------- helper internal ----------
create function public.hash_token(t text) returns text
language sql immutable as $$ select encode(sha256(convert_to(t, 'utf8')), 'hex') $$;

create function public.owner_box(p_username text, p_key text) returns bigint
language plpgsql security definer set search_path = public as $$
declare v bigint;
begin
  select id into v from boxes
   where username = lower(p_username) and key_hash = hash_token(coalesce(p_key, ''));
  if v is null then raise exception 'not_owner'; end if;
  return v;
end $$;

revoke execute on function public.hash_token(text) from public, anon, authenticated;
revoke execute on function public.owner_box(text, text) from public, anon, authenticated;

-- ---------- API publik ----------
create function public.create_box(p_username text, p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  if length(coalesce(p_key, '')) < 32 then raise exception 'bad_key'; end if;
  insert into boxes (username, key_hash) values (p_username, hash_token(p_key)); -- bentrok = error 23505
end $$;

create function public.send_message(p_username text, p_sender text, p_body text) returns void
language plpgsql security definer set search_path = public as $$
declare b public.boxes; sh text; body text := btrim(coalesce(p_body, ''));
begin
  if length(coalesce(p_sender, '')) < 16 then raise exception 'bad_sender'; end if;
  if length(body) not between 1 and 500 then raise exception 'bad_body'; end if;
  select * into b from boxes where username = lower(p_username);
  if not found then raise exception 'no_box'; end if;
  sh := hash_token(p_sender);
  if (select count(*) from messages
       where box_id = b.id and sender_hash = sh and created_at > now() - interval '1 minute') >= 5
  then raise exception 'rate_limited'; end if;
  insert into messages (box_id, sender_hash, body) values (b.id, sh, body);
end $$;

-- Pemilik (kunci cocok) selalu boleh baca. Orang lain baru boleh baca
-- setelah pernah mengirim minimal satu pesan ke kotak ini.
create function public.get_thread(p_username text, p_sender text default null, p_key text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare b public.boxes; is_owner boolean; sh text; viewer boolean; msgs jsonb := '[]'::jsonb;
begin
  select * into b from boxes where username = lower(p_username);
  if not found then return jsonb_build_object('exists', false); end if;
  is_owner := p_key is not null and b.key_hash = hash_token(p_key);
  sh := case when p_sender is null then null else hash_token(p_sender) end;
  viewer := is_owner or (sh is not null and exists (
              select 1 from messages where box_id = b.id and sender_hash = sh));
  if viewer then
    select coalesce(jsonb_agg(jsonb_build_object(
             'id', t.id, 'body', t.body, 'created_at', t.created_at,
             'reply', t.reply, 'replied_at', t.replied_at,
             'mine', coalesce(t.sender_hash = sh, false)) order by t.created_at desc), '[]'::jsonb)
      into msgs
      from (select * from messages where box_id = b.id order by created_at desc limit 200) t;
  end if;
  return jsonb_build_object('exists', true, 'owner', is_owner, 'can_view', viewer, 'messages', msgs);
end $$;

-- ---------- khusus pemilik ----------
create function public.reply_message(p_username text, p_key text, p_id bigint, p_reply text) returns void
language plpgsql security definer set search_path = public as $$
declare bid bigint := owner_box(p_username, p_key); r text := btrim(coalesce(p_reply, ''));
begin
  if length(r) not between 1 and 500 then raise exception 'bad_reply'; end if;
  update messages set reply = r, replied_at = now() where id = p_id and box_id = bid;
end $$;

create function public.delete_message(p_username text, p_key text, p_id bigint) returns void
language plpgsql security definer set search_path = public as $$
declare bid bigint := owner_box(p_username, p_key);
begin
  delete from messages where id = p_id and box_id = bid;
end $$;

grant execute on function
  public.create_box(text, text),
  public.send_message(text, text, text),
  public.get_thread(text, text, text),
  public.reply_message(text, text, bigint, text),
  public.delete_message(text, text, bigint)
to anon, authenticated;
