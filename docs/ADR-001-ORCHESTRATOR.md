# AFTAB ADR-001 | ارزیابی معماری و شکاف نسخه v0.4
Status: Accepted for planning, not deployed.
Date: 2026-10-26
Branch: next/orchestration-v1

## تصمیم اصلی
نسخه v0.4 به‌عنوان research prototype باقی می‌ماند؛ ساخت محصول جدید بر مبنای Control Plane در Go + React و Data Plane استاندارد Xray/sing-box انجام شود. هیچ تغییر پرخطر در سرور فعلی تا کامل‌شدن نمونه آزمایشی مجزا اجرا نشود.

## شواهد از کد واقعی AFTAB
1. `cmd/aftab/ssh_bridge.go`: تونل SSH احرازشده برای دسترسی به listener محلی سرور. به حساب SSH نیاز دارد؛ مناسب انتشار انبوه با root نیست.
2. `cmd/aftab/desktop.go`: خود کد توضیح می‌دهد که only browser TCP proxy است، نه TUN/UDP؛ IP proxy محلی `10808/10809`.
3. `cmd/aftab/main.go`: User name, token digest, expiry, quota bytes, disabled. ایده/منطق مدیریت کاربر قابل انتقال است اما به موتور Xray متصل نیست.
4. `internal/dashboard/dashboard.go`: پنل وب چندزبانه با user creation/disable و gateway status وجود دارد ولی React، node orchestrator، subscriptions و 2FA ندارد.
5. `cmd/aftab/gateway_manager.go`: TLS gateway به صورت loopback اجرا می‌شود و به API runtime هسته استاندارد متصل نیست.

## بررسی رقبا، تصمیم خرید/ساخت
| محصول | قابلیت‌های موجود | چرا AFTAB مستقل توسعه می‌یابد؟ |
|---|---|---|
| 3x-ui | Go panel، چندپروتکله، آمار/سهمیه، اشتراک، multi-node | در حال حاضر روی VPS فعال است؛ آن را کپی یا تغییر نمی‌دهیم. تفاوت AFTAB باید در automation سنجش اپراتور و staged rotation اثبات شود. |
| Marzban | Python/React، REST API، نود، اشتراک/QR | کاربری استاندارد را حل کرده؛ AFTAB باید هزینه کاربری و ریسک rollout را کمتر کند. |
| Hiddify | مدیریت چندپروتکله و مسیرهای CDN، کلاینت | ویژگی‌های زیاد موجود است؛ AFTAB به جای تعویض برند، نیازمند مزیت اندازه‌گیری‌شده است. |
| Remnawave | Xray panel، mTLS، multi-node، REST API و subscription | معماری مرجع برای transport امن panel-node؛ قابلیت‌ها و مجوزها هنگام استفاده از کد باید بررسی شوند. |

## نکات فنی الزام‌آور
- Xray HandlerService/StatsService در API رسمی وجود دارند. ایجاد/حذف کاربر runtime تنها برای پروتکل‌های پشتیبانی‌شده به کار می‌رود. API روی loopback و فقط از Agent با مجوز محدود فراخوانی شود.
- sing-box outbound `urltest` در پیکربندی JSON گروهی کار می‌کند. URI subscription تک‌تک مسیرها را عرضه می‌کند، اما کلاینت معمولاً نیازمند پیکربندی گروه مستقل است.
- Xray `REALITY` از transport RAW/XHTTP/gRPC پشتیبانی می‌کند، ولی REALITY مستقیم معادل یک endpoint CDN با WS/TLS نیست؛ برای هر transport باید تست سازگاری و خروجی اختصاصی داشت.
- مخفی‌شدن واقعی IP سرور و مقاومت در برابر IP-block تنها با تغییر تصویر TLS محقق نمی‌شود. CDN سازگار یا نود پشتیبان نیاز است.
- random URL path صرفاً کاهش سطح کشف تصادفی است و جایگزین احراز هویت، ACL، mTLS و 2FA نیست.
- ShadowTLS/AnyTLS/Hysteria2/TUIC در MVP پایه به کار نروند؛ در فازهای بعد در صورت client compatibility و آزمایش روی اپراتور اضافه شوند.
- هیچ ادعایی درباره «هیچ اپراتوری نمی‌تواند ببندد» مجاز نیست.

## قراردادهای اولیه API (Design draft)
### Control API (local/auth only)
- `POST /api/v1/users`: حساب + روزهای اعتبار + quota.
- `POST /api/v1/devices`: device identity مستقل از account؛ محدودیت اتصال مستقل.
- `POST /api/v1/nodes`: ثبت Agent با one-time bootstrap و mTLS؛ تا فاز چندنودی، یک نود.
- `POST /api/v1/users/{id}/disable`: صدور فرمان revoke به Agent و audit.
- `GET /api/v1/users/{id}/usage`: آمار تجمعی و بازه‌ای با تأخیر مجاز.
- `GET /api/v1/health`: بدون اطلاعات خصوصی.
### Subscription (HTTPS, separate from admin)
- `GET /s/{opaqueDeviceToken}`: خروجی URI استاندارد برای کلاینت‌های ساده.
- `GET /s/{opaqueDeviceToken}?format=sing-box`: config JSON شامل selector/urltest در صورت وجود چند مسیر compatible.
- پاسخ `Cache-Control: no-store` و جلوگیری از ثبت URL token در access logs؛ لینک قابل تعویض و revoke.
- لینک دستگاه هرگز مجوز SSH یا دسترسی API مدیریت ندارد.

## معیارهای فوری
1. `go test ./...` موفق در CI.
2. generate و validate config در حالت dry-run، no deployment، بدون نیاز به SSH تعاملی برای کاربران نهایی.
3. ایجاد حساب از UI و تغییر runtime Xray بدون restart، تست ادغامی با نمونه جدا.
4. دانلود subscription اختصاصی و import موفق در یک کلاینت Windows و یک کلاینت Android.
5. تست امنیت: کلید و توکن در console/log/response دیگران ظاهر نشود؛ revoke موثر باشد.
6. مقایسه SHA256 از release assets پیش از نصب و امکان rollback.
7. کنترل عدم تداخل: fingerprints و ports سرویس‌های 3x-ui و Xray فعلی قبل/بعد برابر.

## محدوده فاز ۰
Document status is not test pass. Until runtime evidence exists all capabilities except inherited v0.4 are DESIGN only.

## مستندات مرجع
- https://xtls.github.io/en/config/api.html
- https://sing-box.sagernet.org/configuration/outbound/urltest/
- https://xtls.github.io/en/config/transports/reality.html
- https://github.com/MHSanaei/3x-ui/
- https://gozargah.github.io/marzban/en/docs/introduction
- https://github.com/hiddify/Hiddify-Manager
- https://docs.rw/
