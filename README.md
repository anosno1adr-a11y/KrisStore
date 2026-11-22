# SHOP NOVA — Glass Edition

Trang shop + trang admin giao diện **Liquid Glass** (kính mờ, blur + aurora gradient), nối backend Supabase thật của shop-fullstack — bán được ngay, không phải bản demo LocalStorage.

## Trang
- `index.html` — Trang shop cho khách: đăng ký/đăng nhập, ví, nạp tiền VietQR (tạo mã NAP...), mua hàng giao key/file tự động, lịch sử đơn.
- `admin.html` — Trang quản trị: tổng quan doanh thu, sản phẩm + kho key, duyệt nạp, khách hàng (± tiền, khoá/mở), đơn hàng, cài đặt shop/ngân hàng/Zalo.
- `schema.sql` — Database + RPC cho Supabase (chỉ chạy 1 lần khi dựng project mới; project hiện tại đã chạy rồi).

## Backend
- Supabase project `shop-fullstack` (Singapore) — URL + publishable key đã nối sẵn trong 2 file HTML.
- Publishable key là khoá công khai, an toàn để trong HTML: dữ liệu được bảo vệ bằng RLS + kiểm tra phiên/mật khẩu admin trong từng hàm RPC. Không bao giờ để `service_role` key vào HTML.

## Chạy trên GitHub Pages
Repo Settings → Pages → Source: Deploy from a branch → `main` / `(root)` → Save.
- Shop: `https://<user>.github.io/<repo>/`
- Admin: `https://<user>.github.io/<repo>/admin.html`

## Việc đầu tiên sau khi mở
1. Vào `admin.html` → đăng nhập bằng mật khẩu admin đã đặt (lần đầu chưa đặt thì hệ thống cho đặt, tối thiểu 8 ký tự).
2. Admin → Sản phẩm → Kho: thêm key/hàng cho từng sản phẩm.
3. Admin → Cài đặt: kiểm tra tên shop, tài khoản MB Bank nhận tiền, Zalo hỗ trợ.
