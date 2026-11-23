# 🛡️ BÁO CÁO KỸ THUẬT & THỰC HÀNH AN TOÀN THÔNG TIN
# WAF DEVSECOPS LAB & SOC AUTOMATED DEFENSE PLATFORM

[![GitHub Repository](https://img.shields.io/badge/GitHub-ThucKieuDuy%2Fwaf--lab-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ThucKieuDuy/waf-lab.git)
[![Docker](https://img.shields.io/badge/Docker-Compose_v2-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![ModSecurity](https://img.shields.io/badge/WAF-ModSecurity_v3-red?style=for-the-badge&logo=nginx&logoColor=white)](https://github.com/owasp-modsecurity/ModSecurity)
[![OWASP CRS](https://img.shields.io/badge/Ruleset-OWASP_CRS_v3.3-orange?style=for-the-badge&logo=owasp&logoColor=white)](https://coreruleset.org/)
[![Python](https://img.shields.io/badge/Python-3.10_Asyncio-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Database](https://img.shields.io/badge/Database-SQLite_WAL-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)

---

## 📋 THÔNG TIN BÁO CÁO THỰC TẬP / ĐỒ ÁN
* **Đề tài:** Xây dựng Hệ thống Phòng thủ Ứng dụng Web (WAF), Tự động hóa Phản ứng Sự cố (SOAR) và Giám sát An ninh (SOC) trên Môi trường DevSecOps.
* **Người thực hiện:** Kiều Duy Thức ([@ThucKieuDuy](https://github.com/ThucKieuDuy))
* **Repository:** [https://github.com/ThucKieuDuy/waf-lab.git](https://github.com/ThucKieuDuy/waf-lab.git)
* **Vị trí định hướng:** Security Engineer / SOC Analyst / DevSecOps Engineer

---

## 📑 MỤC LỤC
1. [TỔNG QUAN DỰ ÁN (TÔI ĐANG LÀM GÌ & ĐÃ HỌC ĐƯỢC GÌ)](#1-tổng-quan-dự-án-tôi-đang-làm-gì--đã-học-được-gì)
2. [KIẾN TRÚC HỆ THỐNG & HẠ TẦNG CONTAINER](#2-kiến-trúc-hệ-thống--hạ-tầng-container)
3. [CHI TIẾT CÁC THÀNH PHẦN & KỊCH BẢN THỰC NGHIỆM](#3-chi-tiết-các-thành-phần--kịch-bản-thực-nghiệm)
8. [HƯỚNG DẪN CÀI ĐẶT & XỬ LÝ SỰ CỐ (TROUBLESHOOTING)](#8-hướng-dẫn-cài-đặt--xử-lý-sự-cố-troubleshooting)

---

## 1. TỔNG QUAN DỰ ÁN (TÔI ĐANG LÀM GÌ & ĐÃ HỌC ĐƯỢC GÌ)

### 1.1. Tôi đang làm gì? (Mục tiêu dự án)
Dự án này là môi trường phòng lab thực nghiệm an toàn thông tin toàn diện, mô phỏng hạ tầng phòng thủ thực tế tại doanh nghiệp nhằm giải quyết 3 bài toán trọng tâm:
1. **Bảo vệ ứng dụng web (Perimeter Defense):** Triển khai WAF ModSecurity v3 kết hợp bộ luật quốc tế OWASP Core Rule Set (CRS v3.3) để ngăn chặn các cuộc tấn công web phổ biến (SQL Injection, XSS, RCE, LFI/RFI).
2. **Chủ động phản ứng tự động (SOAR - Active Defense):** Xây dựng bot phản ứng 2 chiều qua Telegram kết hợp Docker Socket, giúp chuyên viên SOC có thể tra cứu và **chặn đứng IP kẻ tấn công chỉ với 1 chạm (1-click)**, giảm thời gian xử lý sự cố (MTTR) từ hàng chục phút xuống **< 1.5 giây**.
3. **Giám sát thời gian thực & Kiểm thử tự động (SOC & DevSecOps):** Xây dựng SOC Dashboard sử dụng cơ chế **SQLite WAL Mode** (độ trễ truy vấn < 1ms) và bộ công cụ **WAF Scanner** đánh giá tỷ lệ bảo vệ tự động với tiêu chuẩn Quality Gate ($\ge 90\%$).

### 1.2. Tôi đã học được gì từ quá trình này? (Thu hoạch & Kỹ năng đạt được)
* **Kiến thức WAF & OWASP CRS chuyên sâu:**
  * Hiểu bản chất cơ chế chấm điểm bất thường liên hoàn (**Collaborative Anomaly Scoring**) khác biệt hoàn toàn với phương pháp so khớp từ khóa (Regex Signature) truyền thống.
  * Nắm vững cách cấu hình **Paranoia Levels (Level 2)** để cân bằng tối ưu giữa việc chặn đứng kỹ thuật né tránh (Evasion/Obfuscation) và hạn chế báo động giả (False Positive).
  * Thành thạo bóc tách và phân tích các Section trong file ModSecurity Audit Log JSON (Transaction ID, Rule ID, Inbound Score).
* **Tư duy Blue Team & Vận hành SOC/SOAR:**
  * Chuyển dịch từ tư duy phòng thủ thụ động (chỉ ghi log) sang phòng thủ chủ động (tự động hóa cách ly IP tại tầng Nginx sơ cấp).
  * Giải quyết bài toán quá tải cảnh báo (**Alert Fatigue**) bằng cách xây dựng thuật toán điều tiết tốc độ (Rate Limiting) và cơ chế **Flood Shield** tự động gộp bản tin khi bị tấn công dồn dập.
* **Kỹ năng Kỹ thuật Hệ thống & Tối ưu hóa (System Engineering):**
  * Làm chủ lập trình bất đồng bộ (`asyncio`) với mô hình 4 workers chạy song song trên một Event Loop duy nhất mà không gây nghẽn tiến trình.
  * Tối ưu hóa I/O Database với **SQLite WAL Mode** (Write-Ahead Logging), loại bỏ hoàn toàn hiện tượng khóa file (Database Lock) khi vừa ghi vừa đọc dữ liệu tốc độ cao.
  * Ứng dụng kỹ thuật **Streaming Generator** trong Python để nạp hàng chục nghìn payload từ điển mà mức chiếm dụng RAM xấp xỉ bằng 0.
* **Tư duy DevSecOps & Tự vệ hệ thống (Self-Defense):**
  * Tích hợp kiểm thử bảo mật tự động vào chu trình phát triển (Shift-Left Security), đặt điều kiện Quality Gate rõ ràng trước khi triển khai sản phẩm.
  * Chủ động phòng chống tấn công ngược vào chính hệ thống quản trị: lọc IP dải RFC1918 chống **Self-DoS** (chặn nhầm Gateway) và kiểm định Regex chống **Command Injection**.

---

## 2. KIẾN TRÚC HỆ THỐNG & HẠ TẦNG CONTAINER

Toàn bộ hệ thống được container hóa và cô lập trong subnet mạng Bridge `waf_net` (`172.20.0.0/16`). Chỉ có WAF Proxy (Port 80) và SOC Dashboard (Port 5001) được public ra ngoài máy host.

```
                          [ INTERNET / ATTACKER TRAFFIC ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼ (Port 80)                               ▼ (Port 5001)
     ┌───────────────────────────────┐         ┌───────────────────────────────┐
     │           waf_proxy           │         │         soc_dashboard         │
     │    (owasp/modsecurity-crs)    │         │       (Flask & Tailwind)      │
     │         172.20.0.3            │         │          172.20.0.5           │
     └──────────────┬────────────────┘         └───────────────▲───────────────┘
                    │                                          │
       [Proxy Pass] │ (Internal HTTP)           [Read-only WAL]│ (Latency < 1ms)
                    ▼                                          │
     ┌───────────────────────────────┐         ┌───────────────┴───────────────┐
     │          web_target           │         │         waf_events.db         │
     │       (PHP 8.0 Apache)        │         │      (SQLite WAL Storage)     │
     │         172.20.0.2            │         └───────────────▲───────────────┘
     └──────────────┬────────────────┘                         │
                    │                                          │ [Batch Insert]
     [SQL Queries]  │ (Port 3306)                              │
                    ▼                                          │
     ┌───────────────────────────────┐         ┌───────────────┴───────────────┐
     │         waf_mysql_db          │         │          log_parser           │
     │          (MySQL 8.0)          │         │    (Async Daemon & SOAR Bot)  │
     │         172.20.0.4            │         │          172.20.0.6           │
     └───────────────────────────────┘         └───────────┬──────────┬────────┘
                                                           │          │
                 [Tails /var/log/modsecurity/audit.log]    │          │
                 ──────────────────────────────────────────┘          │
                                                                      │ [Docker Socket]
                                [2-Way Telegram Alerts & Callback]    ▼
                                ────────────────────────────────► /var/run/docker.sock
                                                                 (Nginx Reload)
```

### Bảng công nghệ cốt lõi:
| Thành phần | Công nghệ | Vai trò kỹ thuật |
| :--- | :--- | :--- |
| **WAF Reverse Proxy** | ModSecurity v3 + OWASP CRS v3.3 | Phân tích HTTP Request, tính điểm Anomaly Score và chặn đứng tấn công (403 Forbidden) |
| **Ứng dụng mục tiêu** | PHP 8.0 Apache & MySQL 8.0 | Web mục tiêu chứa sẵn lỗ hổng SQLi (`index.php`) và XSS (`comments.php`) phục vụ kiểm thử |
| **Daemon & SOAR Bot** | Python 3.10 Asyncio + Docker Socket | Bóc tách log JSON theo thời gian thực, gửi cảnh báo Telegram và tự động cập nhật `block.conf` |
| **Cơ sở dữ liệu SOC** | SQLite 3 (Chế độ WAL Mode) | Lưu trữ tập trung các sự kiện tấn công, hỗ trợ ghi batch và đọc đồng thời độ trễ cực thấp |
| **SOC Dashboard** | Flask Framework + TailwindCSS | Giao diện giám sát trực quan Dark Mode, cung cấp RESTful APIs quản trị cho SOC Analyst |
| **WAF Scanner** | 100% Python Standard Library | Công cụ bắn tải kiểm thử tự động, đánh giá tỷ lệ bảo vệ Quality Gate ($\ge 90\%$) |

---

## 3. CHI TIẾT CÁC THÀNH PHẦN & KỊCH BẢN THỰC NGHIỆM

### 3.1. Phân tích các thành phần chính
* **Cơ chế Anomaly Scoring (ModSecurity):** Thiết lập `PARANOIA=2`, `ANOMALY_INBOUND=5`. Mỗi vi phạm được chấm điểm theo trọng số. Khi tổng điểm $\ge 5$, Rule ID `949110` sẽ kích hoạt và trả mã `403 Forbidden`.
* **Cơ chế Chặn IP Động (SOAR):** Khi chuyên viên nhấn `[🚫 Chặn IP]` trên Telegram, daemon kiểm tra tính hợp lệ của IP, chèn dòng `deny <IP>;` vào `nginx_conf/block.conf` và nạp lại Nginx qua Docker Socket. Mọi gói tin từ IP này sau đó bị Nginx ngắt ngay tại tầng TCP/HTTP đầu tiên, tiết kiệm tài nguyên hệ thống.
* **Tối ưu hóa SQLite WAL Engine:** Áp dụng `PRAGMA journal_mode = WAL;` và `PRAGMA synchronous = NORMAL;`, cho phép Dashboard truy vấn aggregated data dưới **0.2ms** mà không làm khóa tiến trình ghi log.

### 3.2. Tóm tắt 7 kịch bản thực nghiệm đã kiểm chứng
1. **Kịch bản 1 - Ngăn chặn SQL Injection (Auth Bypass):**
   * *Thao tác:* Nhập payload `admin' --` vào trang đăng nhập `http://localhost/index.php`.
   * *Kết quả:* WAF kích hoạt Rule ID `942100` (libinjection), trả mã **403 Forbidden**, gửi cảnh báo đỏ tức thì về Telegram và cập nhật Dashboard.
2. **Kịch bản 2 - Ngăn chặn Stored XSS:**
   * *Thao tác:* Gửi request `curl -X POST http://localhost/comments.php -d 'content=<script>alert("XSS")</script>'`.
   * *Kết quả:* WAF kích hoạt Rule ID `941100`, chặn đứng payload không cho lưu vào CSDL MySQL.
3. **Kịch bản 3 - Phản ứng sự cố SOAR 2 chiều (Chặn & Mở khóa IP):**
   * *Thao tác:* Nhận cảnh báo tấn công từ IP `203.0.113.88` trên Telegram $\rightarrow$ Nhấn nút `[🚫 Chặn IP]`.
   * *Kết quả:* File `block.conf` tự động thêm `deny 203.0.113.88;`, Nginx reload lập tức. Nút bấm trên Telegram tự đổi sang `[🟢 Mở khóa (Unban)]` cho phép phục hồi quyền truy cập bất kỳ lúc nào.
4. **Kịch bản 4 - Tra cứu Threat Intel nội bộ:**
   * *Thao tác:* Nhấn nút `[🔍 Info IP]` trên Telegram.
   * *Kết quả:* Bot tổng hợp ngay trong chat: Tổng số request, số lần bị chặn, tỷ lệ bypass và các URI mà IP này đã nhắm tới.
5. **Kịch bản 5 - Kiểm chứng cơ chế Tự vệ (Self-Defense):**
   * *Thao tác:* Thử chặn IP Gateway `172.20.0.1` hoặc chèn chuỗi độc hại `1.2.3.4; rm -rf /`.
   * *Kết quả:* Hệ thống từ chối lệnh chặn mạng nội bộ (chống **Self-DoS**) và Regex lọc sạch chuỗi độc hại (chống **Command Injection**).
6. **Kịch bản 6 - Bắn tải WAF Scanner & Đánh giá Quality Gate:**
   * *Thao tác:* Chạy lệnh `python3 waf_scanner.py --limit=50`.
   * *Kết quả:* Hệ thống kích hoạt **Flood Shield** chống nghẽn Telegram; tỷ lệ phòng vệ đạt **96.2%**, vượt tiêu chuẩn Quality Gate ($\ge 90\%$).
7. **Kịch bản 7 - Dọn dẹp & Reset môi trường (`reset_traffic.sh`):**
   * *Thao tác:* Chạy lệnh `./reset_traffic.sh`.
   * *Kết quả:* Tự động làm sạch log, dọn bảng SQLite (`VACUUM`), xóa IP trong `block.conf` và khôi phục database về trạng thái ban đầu trong 3 giây.

---

## 4. HƯỚNG DẪN CÀI ĐẶT & XỬ LÝ SỰ CỐ (TROUBLESHOOTING)

### 4.1. Hướng dẫn khởi chạy nhanh (3 bước)
```bash
# Bước 1: Clone kho mã nguồn dự án
git clone https://github.com/ThucKieuDuy/waf-lab.git
cd waf-lab

# Bước 2: Thiết lập cấu hình biến môi trường
cp .env.example .env
# (Chỉnh sửa TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID trong .env nếu muốn nhận cảnh báo)

# Bước 3: Khởi chạy toàn bộ hệ thống bằng Docker Compose
docker compose up -d --build
```

**Các liên kết truy cập sau khi khởi động:**
* **Ứng dụng Web Target (Có WAF bảo vệ):** [http://localhost/](http://localhost/)
* **Trung tâm Giám sát SOC Dashboard:** [http://localhost:5001/](http://localhost:5001/)
* **API Thống kê Sự kiện SOC:** [http://localhost:5001/api/stats](http://localhost:5001/api/stats)

---

### 4.2. Hướng dẫn xử lý sự cố thường gặp (Troubleshooting)

| Hiện tượng | Nguyên nhân | Giải pháp xử lý |
| :--- | :--- | :--- |
| **Xung đột cổng `80` hoặc `5001`** | Máy host đã có dịch vụ Web/Flask khác đang chạy | Tìm và tắt tiến trình xung đột: `lsof -i :80` hoặc `lsof -i :5001` rồi kill tiến trình |
| **Lỗi quyền truy cập Docker Socket** | User máy host không có quyền đọc `/var/run/docker.sock` | Cấp quyền nhanh: `sudo chmod 666 /var/run/docker.sock` |
| **Bot Telegram không gửi tin nhắn** | `TELEGRAM_BOT_TOKEN` hoặc `CHAT_ID` chưa đúng | Kiểm tra lại token với `@BotFather`, gửi tin nhắn mồi cho Bot rồi lấy Chat ID qua API `getUpdates` |
| **Dashboard không nhảy số sự kiện** | File database chưa được cấp quyền ghi | Kiểm tra log daemon: `docker compose logs -f log_parser` và đảm bảo thư mục `./logs` có quyền ghi |
| **Quét WAF Scanner gây quá tải CPU** | Số luồng quét mặc định quá cao so với cấu hình máy | Giảm worker và tăng độ trễ: `python3 waf_scanner.py --workers=4 --delay=0.05` |
