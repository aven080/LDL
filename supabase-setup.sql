-- Local Demonlist account + profile claim setup
-- Run this entire file in Supabase Dashboard -> SQL Editor -> New query.

create extension if not exists pgcrypto;

create table if not exists public.player_profiles (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  display_name text unique not null,
  user_id uuid unique references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.profile_claims (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  profile_id uuid not null references public.player_profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create unique index if not exists one_pending_claim_per_user
on public.profile_claims(user_id)
where status = 'pending';

create unique index if not exists one_pending_claim_per_profile
on public.profile_claims(profile_id)
where status = 'pending';

insert into public.player_profiles (slug, display_name)
values
  ('aven','Aven'),
  ('ian','Ian'),
  ('cylus','Cylus'),
  ('marshall','Marshall')
on conflict (slug) do update set display_name = excluded.display_name;

alter table public.player_profiles enable row level security;
alter table public.profile_claims enable row level security;

-- Because automatic table exposure/grants may be disabled, explicitly allow
-- the browser roles to access these tables. RLS policies below still control
-- which rows each role may read or create.
grant usage on schema public to anon, authenticated;
grant select on table public.player_profiles to anon, authenticated;
grant select, insert on table public.profile_claims to authenticated;

-- Anyone may read player names and whether they are already linked.
drop policy if exists "Public can read player profiles" on public.player_profiles;
create policy "Public can read player profiles"
on public.player_profiles for select
to anon, authenticated
using (true);

-- Signed-in users may view only their own claim requests.
drop policy if exists "Users can read own claims" on public.profile_claims;
create policy "Users can read own claims"
on public.profile_claims for select
to authenticated
using (auth.uid() = user_id);

-- Signed-in users may create only their own pending claims, and only for unclaimed profiles.
drop policy if exists "Users can create own claims" on public.profile_claims;
create policy "Users can create own claims"
on public.profile_claims for insert
to authenticated
with check (
  auth.uid() = user_id
  and status = 'pending'
  and exists (
    select 1 from public.player_profiles p
    where p.id = profile_id and p.user_id is null
  )
);

-- No browser-side update/delete policies are intentionally created.
-- Approve claims manually in the Supabase dashboard with the helper function below.

create or replace function public.approve_profile_claim(claim_uuid uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  claim_row public.profile_claims%rowtype;
begin
  select * into claim_row
  from public.profile_claims
  where id = claim_uuid and status = 'pending'
  for update;

  if not found then
    raise exception 'Pending claim not found';
  end if;

  if exists (select 1 from public.player_profiles where id = claim_row.profile_id and user_id is not null) then
    raise exception 'Player profile is already linked';
  end if;

  update public.player_profiles
  set user_id = claim_row.user_id
  where id = claim_row.profile_id;

  update public.profile_claims
  set status = 'approved', reviewed_at = now()
  where id = claim_uuid;

  update public.profile_claims
  set status = 'rejected', reviewed_at = now()
  where profile_id = claim_row.profile_id
    and id <> claim_uuid
    and status = 'pending';
end;
$$;

revoke all on function public.approve_profile_claim(uuid) from public, anon, authenticated;

-- To approve a claim:
-- 1. Open Table Editor -> profile_claims and copy the pending claim's id.
-- 2. Run: select public.approve_profile_claim('PASTE-CLAIM-ID-HERE');

-- Registered account search + profile pictures
alter table public.player_profiles
add column if not exists avatar_url text;

grant update (avatar_url) on table public.player_profiles to authenticated;

drop policy if exists "Users can update own profile picture" on public.player_profiles;
create policy "Users can update own profile picture"
on public.player_profiles for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'profile-pictures',
  'profile-pictures',
  true,
  5242880,
  array['image/png','image/jpeg','image/webp']
)
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Public can view profile pictures" on storage.objects;
create policy "Public can view profile pictures"
on storage.objects for select
to public
using (bucket_id = 'profile-pictures');

drop policy if exists "Users can upload own profile picture" on storage.objects;
create policy "Users can upload own profile picture"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'profile-pictures'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "Users can update own profile picture file" on storage.objects;
create policy "Users can update own profile picture file"
on storage.objects for update
to authenticated
using (
  bucket_id = 'profile-pictures'
  and (storage.foldername(name))[1] = auth.uid()::text
)
with check (
  bucket_id = 'profile-pictures'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "Users can delete own profile picture file" on storage.objects;
create policy "Users can delete own profile picture file"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'profile-pictures'
  and (storage.foldername(name))[1] = auth.uid()::text
);
