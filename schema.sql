-- ============================================================
-- SHOP FULLSTACK — Schema + RPC cho Supabase (PostgreSQL)
-- Cách dùng: Supabase Dashboard > SQL Editor > dán toàn bộ > Run.
-- Kiến trúc: bật RLS khoá cứng mọi bảng; frontend chỉ gọi RPC
-- (SECURITY DEFINER) bằng anon key. Mọi kiểm tra phiên/quyền
-- đều nằm trong hàm SQL, chạy nguyên tử theo transaction.
-- ============================================================

create extension if not exists pgcrypto;

-- ---------------- BẢNG ----------------
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text not null,
  pass_hash text not null,
  balance bigint not null default 0,
  status text not null default 'active',
  created_at timestamptz not null default now()
);
create unique index if not exists users_username_lower_idx on public.users (lower(username));

create table if not exists public.sessions (
  token text primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days'
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  category text not null default 'KEY',
  price bigint not null default 0,
  description text not null default '',
  image_url text not null default '',
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.stock_notes (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  content text not null,
  used boolean not null default false,
  order_id uuid,
  created_at timestamptz not null default now()
);
create index if not exists stock_notes_product_idx on public.stock_notes (product_id, used);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  product_id uuid,
  product_name text not null,
  price bigint not null,
  note_content text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.deposits (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  user_id uuid not null references public.users(id) on delete cascade,
  amount bigint not null,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  decided_at timestamptz
);

create table if not exists public.config (
  key text primary key,
  value text not null default ''
);

-- Khoá cứng: không policy nào => anon/authenticated không đọc/ghi trực tiếp được.
alter table public.users enable row level security;
alter table public.sessions enable row level security;
alter table public.products enable row level security;
alter table public.stock_notes enable row level security;
alter table public.orders enable row level security;
alter table public.deposits enable row level security;
alter table public.config enable row level security;

-- ---------------- HÀM PHỤ (nội bộ) ----------------
create or replace function public._auth_user(p_token text)
returns public.users
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users;
begin
  if p_token is null or p_token = '' then return null; end if;
  select users.* into u
    from public.sessions s join public.users on users.id = s.user_id
   where s.token = p_token and s.expires_at > now();
  if u.id is null or u.status <> 'active' then return null; end if;
  return u;
end $$;

create or replace function public._is_admin(p_admin_token text)
returns boolean
language plpgsql security definer set search_path = public, extensions
as $$
declare h text;
begin
  select value into h from public.config where key = 'admin_token_hash';
  if h is null or h = '' or p_admin_token is null or p_admin_token = '' then return false; end if;
  return extensions.crypt(p_admin_token, h) = h;
end $$;

create or replace function public._gen_deposit_code()
returns text
language plpgsql security definer set search_path = public, extensions
as $$
declare
  chars constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  v_code text; i int;
begin
  loop
    v_code := 'NAP';
    for i in 1..10 loop
      v_code := v_code || substr(chars, 1 + floor(random() * length(chars))::int, 1);
    end loop;
    exit when not exists (select 1 from public.deposits d where d.code = v_code);
  end loop;
  return v_code;
end $$;

-- ---------------- KHÁCH: TÀI KHOẢN ----------------
create or replace function public.register_user(p_username text, p_password text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare uname text := trim(coalesce(p_username, ''));
begin
  if length(uname) < 3 then return jsonb_build_object('success', false, 'error', 'Tên đăng nhập tối thiểu 3 ký tự'); end if;
  if length(coalesce(p_password, '')) < 6 then return jsonb_build_object('success', false, 'error', 'Mật khẩu tối thiểu 6 ký tự'); end if;
  if exists (select 1 from public.users where lower(username) = lower(uname)) then
    return jsonb_build_object('success', false, 'error', 'Tên đăng nhập đã tồn tại');
  end if;
  insert into public.users (username, pass_hash)
  values (uname, extensions.crypt(p_password, extensions.gen_salt('bf')));
  return jsonb_build_object('success', true);
end $$;

create or replace function public.login_user(p_username text, p_password text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users; tok text;
begin
  select * into u from public.users where lower(username) = lower(trim(coalesce(p_username, '')));
  if u.id is null or extensions.crypt(coalesce(p_password, ''), u.pass_hash) <> u.pass_hash then
    return jsonb_build_object('success', false, 'error', 'Sai tên đăng nhập hoặc mật khẩu');
  end if;
  if u.status <> 'active' then
    return jsonb_build_object('success', false, 'error', 'Tài khoản đã bị khoá');
  end if;
  tok := encode(extensions.gen_random_bytes(24), 'hex');
  insert into public.sessions (token, user_id) values (tok, u.id);
  return jsonb_build_object('success', true, 'session_token', tok,
    'user', jsonb_build_object('username', u.username, 'balance', u.balance));
end $$;

create or replace function public.get_me(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users := public._auth_user(p_token);
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;
  return jsonb_build_object('success', true,
    'user', jsonb_build_object('username', u.username, 'balance', u.balance, 'created_at', u.created_at));
end $$;

create or replace function public.logout_user(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  delete from public.sessions where token = p_token;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.change_password(p_token text, p_old text, p_new text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users := public._auth_user(p_token);
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;
  if extensions.crypt(coalesce(p_old, ''), u.pass_hash) <> u.pass_hash then
    return jsonb_build_object('success', false, 'error', 'Mật khẩu cũ không đúng');
  end if;
  if length(coalesce(p_new, '')) < 6 then return jsonb_build_object('success', false, 'error', 'Mật khẩu mới tối thiểu 6 ký tự'); end if;
  update public.users set pass_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = u.id;
  return jsonb_build_object('success', true);
end $$;

-- ---------------- CÔNG KHAI: SẢN PHẨM + CẤU HÌNH ----------------
create or replace function public.list_products()
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', p.id, 'name', p.name, 'category', p.category, 'price', p.price,
      'description', p.description, 'image_url', p.image_url,
      'remaining', (select count(*) from public.stock_notes n where n.product_id = p.id and not n.used)
    ) order by p.sort, p.created_at)
    from public.products p where p.active
  ), '[]'::jsonb);
end $$;

create or replace function public.get_config()
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  return coalesce((
    select jsonb_object_agg(key, value) from public.config
     where key in ('shop_name', 'bank_name', 'bank_account', 'bank_holder', 'bank_bin', 'support_zalo', 'support_text')
  ), '{}'::jsonb);
end $$;

-- ---------------- KHÁCH: VÍ / NẠP / MUA ----------------
create or replace function public.create_deposit(p_token text, p_amount bigint)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users := public._auth_user(p_token); code text;
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;
  if p_amount is null or p_amount < 10000 then return jsonb_build_object('success', false, 'error', 'Số tiền nạp tối thiểu 10.000đ'); end if;
  code := public._gen_deposit_code();
  insert into public.deposits (code, user_id, amount) values (code, u.id, p_amount);
  return jsonb_build_object('success', true, 'code', code, 'amount', p_amount);
end $$;

create or replace function public.my_deposits(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users := public._auth_user(p_token);
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;
  return jsonb_build_object('success', true, 'deposits', coalesce((
    select jsonb_agg(jsonb_build_object('code', d.code, 'amount', d.amount, 'status', d.status, 'created_at', d.created_at) order by d.created_at desc)
    from public.deposits d where d.user_id = u.id
  ), '[]'::jsonb));
end $$;

create or replace function public.buy_product(p_token text, p_product_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  u public.users := public._auth_user(p_token);
  p public.products;
  n public.stock_notes;
  oid uuid;
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;

  -- Khoá hàng user + sản phẩm: chống mua trùng / trừ tiền 2 lần khi bấm liên tục.
  select * into u from public.users where id = u.id for update;
  select * into p from public.products where id = p_product_id and active;
  if p.id is null then return jsonb_build_object('success', false, 'error', 'Sản phẩm không tồn tại'); end if;
  if u.balance < p.price then return jsonb_build_object('success', false, 'error', 'Số dư không đủ, vui lòng nạp thêm'); end if;

  select * into n from public.stock_notes
   where product_id = p.id and not used
   order by created_at
   for update skip locked
   limit 1;
  if n.id is null then return jsonb_build_object('success', false, 'error', 'Sản phẩm tạm hết hàng'); end if;

  insert into public.orders (user_id, product_id, product_name, price, note_content)
  values (u.id, p.id, p.name, p.price, n.content)
  returning id into oid;

  update public.stock_notes set used = true, order_id = oid where id = n.id;
  update public.users set balance = balance - p.price where id = u.id;

  return jsonb_build_object('success', true, 'order_id', oid,
    'product_name', p.name, 'price', p.price, 'delivered', n.content,
    'balance', u.balance - p.price);
end $$;

create or replace function public.my_orders(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare u public.users := public._auth_user(p_token);
begin
  if u.id is null then return jsonb_build_object('success', false, 'error', 'Phiên đăng nhập hết hạn'); end if;
  return jsonb_build_object('success', true, 'orders', coalesce((
    select jsonb_agg(jsonb_build_object('id', o.id, 'product_name', o.product_name, 'price', o.price,
      'note_content', o.note_content, 'created_at', o.created_at) order by o.created_at desc)
    from public.orders o where o.user_id = u.id
  ), '[]'::jsonb));
end $$;

-- ---------------- ADMIN ----------------
-- Lần đầu: admin_setup chỉ chạy được khi chưa có mật khẩu admin.
create or replace function public.admin_setup(p_new_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare h text;
begin
  select value into h from public.config where key = 'admin_token_hash';
  if h is not null and h <> '' then return jsonb_build_object('success', false, 'error', 'Mật khẩu admin đã được đặt'); end if;
  if length(coalesce(p_new_token, '')) < 8 then return jsonb_build_object('success', false, 'error', 'Mật khẩu admin tối thiểu 8 ký tự'); end if;
  insert into public.config (key, value) values ('admin_token_hash', extensions.crypt(p_new_token, extensions.gen_salt('bf')))
  on conflict (key) do update set value = excluded.value;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_login(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare h text;
begin
  select value into h from public.config where key = 'admin_token_hash';
  if h is null or h = '' then return jsonb_build_object('success', false, 'need_setup', true); end if;
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Sai mật khẩu admin'); end if;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_stats(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true,
    'users', (select count(*) from public.users),
    'products', (select count(*) from public.products),
    'orders', (select count(*) from public.orders),
    'revenue', (select coalesce(sum(price), 0) from public.orders),
    'pending_deposits', (select count(*) from public.deposits where status = 'pending'),
    'stock_left', (select count(*) from public.stock_notes where not used));
end $$;

create or replace function public.admin_products(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true, 'products', coalesce((
    select jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name, 'category', p.category, 'price', p.price,
      'description', p.description, 'image_url', p.image_url, 'active', p.active, 'sort', p.sort,
      'remaining', (select count(*) from public.stock_notes n where n.product_id = p.id and not n.used),
      'sold', (select count(*) from public.stock_notes n where n.product_id = p.id and n.used)
    ) order by p.sort, p.created_at)
    from public.products p
  ), '[]'::jsonb));
end $$;

create or replace function public.admin_save_product(p_admin_token text, p_id uuid, p_name text, p_category text,
  p_price bigint, p_description text, p_image_url text, p_active boolean, p_sort int)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare new_id uuid;
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  if trim(coalesce(p_name, '')) = '' then return jsonb_build_object('success', false, 'error', 'Tên sản phẩm trống'); end if;
  if p_id is null then
    insert into public.products (name, category, price, description, image_url, active, sort)
    values (trim(p_name), coalesce(nullif(trim(p_category), ''), 'KEY'), greatest(coalesce(p_price, 0), 0),
            coalesce(p_description, ''), coalesce(p_image_url, ''), coalesce(p_active, true), coalesce(p_sort, 0))
    returning id into new_id;
  else
    update public.products set name = trim(p_name), category = coalesce(nullif(trim(p_category), ''), 'KEY'),
      price = greatest(coalesce(p_price, 0), 0), description = coalesce(p_description, ''),
      image_url = coalesce(p_image_url, ''), active = coalesce(p_active, true), sort = coalesce(p_sort, 0)
    where id = p_id returning id into new_id;
    if new_id is null then return jsonb_build_object('success', false, 'error', 'Sản phẩm không tồn tại'); end if;
  end if;
  return jsonb_build_object('success', true, 'id', new_id);
end $$;

create or replace function public.admin_delete_product(p_admin_token text, p_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  delete from public.products where id = p_id;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_add_notes(p_admin_token text, p_product_id uuid, p_contents text[])
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare c text; added int := 0;
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  if not exists (select 1 from public.products where id = p_product_id) then
    return jsonb_build_object('success', false, 'error', 'Sản phẩm không tồn tại');
  end if;
  foreach c in array coalesce(p_contents, '{}') loop
    if trim(coalesce(c, '')) <> '' then
      insert into public.stock_notes (product_id, content) values (p_product_id, trim(c));
      added := added + 1;
    end if;
  end loop;
  return jsonb_build_object('success', true, 'added', added);
end $$;

create or replace function public.admin_list_notes(p_admin_token text, p_product_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true, 'notes', coalesce((
    select jsonb_agg(jsonb_build_object('id', n.id, 'content', n.content, 'used', n.used, 'created_at', n.created_at) order by n.created_at)
    from public.stock_notes n where n.product_id = p_product_id
  ), '[]'::jsonb));
end $$;

create or replace function public.admin_delete_note(p_admin_token text, p_note_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  delete from public.stock_notes where id = p_note_id and not used;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_deposits(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true, 'deposits', coalesce((
    select jsonb_agg(jsonb_build_object('id', d.id, 'code', d.code, 'username', u.username,
      'amount', d.amount, 'status', d.status, 'created_at', d.created_at) order by d.created_at desc)
    from public.deposits d join public.users u on u.id = d.user_id
  ), '[]'::jsonb));
end $$;

create or replace function public.admin_approve_deposit(p_admin_token text, p_deposit_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare d public.deposits;
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  -- Chỉ duyệt được đơn đang pending: duyệt lại lần 2 không cộng tiền nữa (chống cộng trùng).
  update public.deposits set status = 'approved', decided_at = now()
   where id = p_deposit_id and status = 'pending'
   returning * into d;
  if d.id is null then return jsonb_build_object('success', false, 'error', 'Đơn không tồn tại hoặc đã xử lý'); end if;
  update public.users set balance = balance + d.amount where id = d.user_id;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_reject_deposit(p_admin_token text, p_deposit_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare d public.deposits;
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  update public.deposits set status = 'rejected', decided_at = now()
   where id = p_deposit_id and status = 'pending'
   returning * into d;
  if d.id is null then return jsonb_build_object('success', false, 'error', 'Đơn không tồn tại hoặc đã xử lý'); end if;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_users(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true, 'users', coalesce((
    select jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'balance', u.balance,
      'status', u.status, 'created_at', u.created_at) order by u.created_at desc)
    from public.users u
  ), '[]'::jsonb));
end $$;

create or replace function public.admin_adjust_balance(p_admin_token text, p_user_id uuid, p_delta bigint)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare nb bigint;
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  update public.users set balance = greatest(balance + coalesce(p_delta, 0), 0)
   where id = p_user_id returning balance into nb;
  if nb is null then return jsonb_build_object('success', false, 'error', 'User không tồn tại'); end if;
  return jsonb_build_object('success', true, 'balance', nb);
end $$;

create or replace function public.admin_set_user_status(p_admin_token text, p_user_id uuid, p_status text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  if p_status not in ('active', 'banned') then return jsonb_build_object('success', false, 'error', 'Trạng thái không hợp lệ'); end if;
  update public.users set status = p_status where id = p_user_id;
  if p_status = 'banned' then delete from public.sessions where user_id = p_user_id; end if;
  return jsonb_build_object('success', true);
end $$;

create or replace function public.admin_orders(p_admin_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  return jsonb_build_object('success', true, 'orders', coalesce((
    select jsonb_agg(jsonb_build_object('id', o.id, 'username', u.username, 'product_name', o.product_name,
      'price', o.price, 'created_at', o.created_at) order by o.created_at desc)
    from public.orders o join public.users u on u.id = o.user_id
  ), '[]'::jsonb));
end $$;

create or replace function public.admin_set_config(p_admin_token text, p_key text, p_value text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not public._is_admin(p_admin_token) then return jsonb_build_object('success', false, 'error', 'Không có quyền admin'); end if;
  if p_key not in ('shop_name', 'bank_name', 'bank_account', 'bank_holder', 'bank_bin', 'support_zalo', 'support_text') then
    return jsonb_build_object('success', false, 'error', 'Khoá cấu hình không hợp lệ');
  end if;
  insert into public.config (key, value) values (p_key, coalesce(p_value, ''))
  on conflict (key) do update set value = excluded.value;
  return jsonb_build_object('success', true);
end $$;

-- ---------------- DỮ LIỆU MẪU ----------------
insert into public.config (key, value) values
  ('shop_name', 'SHOP NOVA'),
  ('bank_name', 'MB Bank'),
  ('bank_account', '0834983865'),
  ('bank_holder', 'LUONG TUAN DAN'),
  ('bank_bin', '970422'),
  ('support_zalo', '0336287114'),
  ('support_text', 'Hỗ trợ 24/7 qua Zalo')
on conflict (key) do nothing;

insert into public.products (name, category, price, description, sort)
select * from (values
  ('Key 7 Ngày', 'KEY', 30000, 'Key dùng 7 ngày / 1 máy', 1),
  ('Key 30 Ngày', 'KEY', 80000, 'Key dùng 30 ngày / 1 máy — phổ biến nhất', 2),
  ('Key 90 Ngày', 'KEY', 200000, 'Key dùng 90 ngày / 1 máy', 3),
  ('Key Vĩnh Viễn', 'KEY', 500000, 'Key vĩnh viễn / 1 máy', 4),
  ('File Hỗ Trợ', 'FILE', 50000, 'File giao tự động sau khi mua', 5),
  ('Bot Telegram', 'BOT', 200000, 'Bot Telegram theo yêu cầu', 6)
) as v(name, category, price, description, sort)
where not exists (select 1 from public.products);
