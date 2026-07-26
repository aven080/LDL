-- Run this ONCE in Supabase SQL Editor to enable profile picture uploads.

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
