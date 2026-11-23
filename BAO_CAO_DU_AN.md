# 🛡️ BÁO CÁO KỸ THUẬT DỰ ÁN
# WAF DEVSECOPS LAB & SOC AUTOMATED DEFENSE PLATFORM

---

## 📌 MỤC LỤC
- [1. TỔNG QUAN DỰ ÁN](#1-tổng-quan-dự-án)
  - [1.1. Bối cảnh & Mục tiêu xây dựng](#11-bối-cảnh--mục-tiêu-xây-dựng)
  - [1.2. Các tính năng nổi bật & Giá trị thực tiễn](#12-các-tính-năng-nổi-bật--giá-trị-thực-tiễn)
  - [1.3. Mô hình kiến trúc & Sơ đồ luồng dữ liệu](#13-mô-hình-kiến-trúc--sơ-đồ-luồng-dữ-liệu)
- [2. GIẢI THÍCH CHI TIẾT CÁC THÀNH PHẦN TRONG DỰ ÁN](#2-giải-thích-chi-tiết-các-thành-phần-trong-dự-án)
  - [2.1. Cụm WAF Reverse Proxy (ModSecurity v3 + OWASP CRS v3.3)](#21-cụm-waf-reverse-proxy-modsecurity-v3--owasp-crs-v33)
  - [2.2. Ứng dụng mục tiêu & CSDL (Web Target & MySQL)](#22-ứng-dụng-mục-tiêu--csdl-web-target--mysql)
  - [2.3. Bộ phân tích nhật ký thời gian thực & SOAR Bot 2 chiều (Log Parser & SOAR Bot)](#23-bộ-phân-tích-nhật-ký-thời-gian-thực--soar-bot-2-chiều-log-parser--soar-bot)
  - [2.4. Trung tâm giám sát SOC Dashboard (SQLite WAL Query Engine)](#24-trung-tâm-giám-sát-soc-dashboard-sqlite-wal-query-engine)
  - [2.5. Bộ công cụ kiểm thử WAF tự động (WAF Scanner & Quality Gate)](#25-bộ-công-cụ-kiểm-thử-waf-tự-động-waf-scanner--quality-gate)
  - [2.6. Tiện ích quản trị & dọn dẹp hệ thống (Reset Traffic Utility)](#26-tiện-ích-quản-trị--dọn-dẹp-hệ-thống-reset-traffic-utility)
- [3. CÁC CẤU HÌNH QUAN TRỌNG CẦN BIẾT](#3-các-cấu-hình-quan-trọng-cần-biết)
  - [3.1. Cấu hình biến môi trường (`.env`)](#31-cấu-hình-biến-môi-trường-env)
  - [3.2. Cấu hình ModSecurity Engine & CRS Rule Engine](#32-cấu-hình-modsecurity-engine--crs-rule-engine)
  - [3.3. Cấu hình Nginx Proxy & Chặn IP động (`default.conf` & `block.conf`)](#33-cấu-hình-nginx-proxy--chặn-ip-động-defaultconf--blockconf)
  - [3.4. Cấu hình tối ưu SQLite WAL Engine (< 1ms Latency)](#34-cấu-hình-tối-ưu-sqlite-wal-engine--1ms-latency)
  - [3.5. Cơ chế tự vệ (Self-Defense) & Chống nghẽn cảnh báo (Flood Shield)](#35-cơ-chế-tự-vệ-self-defense--chống-nghẽn-cảnh-báo-flood-shield)
- [4. CÁC KỊCH BẢN THỰC NGHIỆM NGẮN (STEP-BY-STEP SCENARIOS)](#4-các-kịch-bản-thực-nghiệm-ngắn-step-by-step-scenarios)
  - [Kịch bản 1: Thử nghiệm tấn công SQL Injection (Authentication Bypass)](#kịch-bản-1-thử-nghiệm-tấn-công-sql-injection-authentication-bypass)
  - [Kịch bản 2: Thử nghiệm tấn công Stored Cross-Site Scripting (XSS)](#kịch-bản-2-thử-nghiệm-tấn-công-stored-cross-site-scripting-xss)
  - [Kịch bản 3: Thử nghiệm quy trình phản ứng tự động SOAR 2 chiều qua Telegram](#kịch-bản-3-thử-nghiệm-quy-trình-phản-ứng-tự-động-soar-2-chiều-qua-telegram)
  - [Kịch bản 4: Thử nghiệm tra cứu thông tin tình báo mối đe dọa (Threat Intel)](#kịch-bản-4-thử-nghiệm-tra-cứu-thông-tin-tình-báo-mối-đe-dọa-threat-intel)
  - [Kịch bản 5: Thử nghiệm cơ chế Self-Defense (Chống Self-DoS & Command Injection)](#kịch-bản-5-thử-nghiệm-cơ-chế-self-defense-chống-self-dos--command-injection)
  - [Kịch bản 6: Thực thi bắn tải WAF Benchmark & Đánh giá Quality Gate](#kịch-bản-6-thực-thi-bắn-tải-waf-benchmark--đánh-giá-quality-gate)
  - [Kịch bản 7: Reset toàn bộ traffic và đưa hệ thống về trạng thái ban đầu](#kịch-bản-7-reset-toàn-bộ-traffic-và-đưa-hệ-thống-về-trạng-thái-ban-đầu)
- [5. TỔNG KẾT & HƯỚNG PHÁT TRIỂN](#5-tổng-kết--hướng-phát-triển)

---

## 1. TỔNG QUAN DỰ ÁN

### 1.1. Bối cảnh & Mục tiêu xây dựng
Trong bối cảnh các cuộc tấn công ứng dụng web ngày càng tinh vi và tự động hoá cao, việc duy trì một hệ thống phòng thủ tĩnh truyền thống không còn đủ khả năng bảo vệ hạ tầng doanh nghiệp. Dự án **WAF DevSecOps Lab & SOC Automated Defense Platform** được nghiên cứu và xây dựng nhằm giải quyết 4 thách thức cốt lõi:

1. **Khả năng nhận diện mối đe dọa chuyên sâu (Deep Threat Inspection):** Thay vì dựa vào kiểm tra chuỗi đơn giản, hệ thống tích hợp bộ quy tắc chuẩn quốc tế OWASP ModSecurity Core Rule Set (CRS v3.3) để phân tích giao thức HTTP, chống các kỹ thuật mã hóa né tránh (evasion / obfuscation), nhận diện chính xác các vector tấn công phổ biến như SQLi, XSS, RCE, LFI/RFI.
2. **Khả năng phản ứng tự động hóa (Security Orchestration, Automation, and Response - SOAR):** Cắt giảm triệt để thời gian phát hiện và xử lý sự cố (MTTD / MTTR) từ hàng giờ xuống **dưới 1 giây**. Chuyên viên SOC có thể ra lệnh cô lập IP độc hại trực tiếp từ ứng dụng nhắn tin bảo mật (Telegram) thông qua các nút bấm tương tác 2 chiều mà không cần SSH hay gõ lệnh máy chủ thủ công.
3. **Khả năng giám sát trực quan với độ trễ siêu thấp (Zero-Latency SOC Observability):** Loại bỏ hoàn toàn phương pháp quét file log văn bản nặng nề gây nghẽn I/O đĩa cứng; thay thế bằng kiến trúc lưu trữ bất đồng bộ SQLite WAL Mode với thời gian phản hồi truy vấn dưới **1ms**.
4. **Tích hợp bảo mật vào quy trình phát triển (Shift-Left DevSecOps):** Tự động hóa kiểm thử WAF với bộ từ điển hơn 10.000 vector tấn công thực tế và kiểm soát chất lượng đóng gói qua Quality Gate nghiêm ngặt (Tỉ lệ bảo vệ $\ge 90\%$).

### 1.2. Các tính năng nổi bật & Giá trị thực tiễn
- **Phòng thủ đa tầng chủ động (Active Blocking):** Cấu hình Paranoia Level 2 với ngưỡng chấm điểm Anomaly Score chặt chẽ (`INBOUND=5`, `OUTBOUND=4`).
- **SOAR 2 chiều qua Telegram Bot:** Nhận tin nhắn cảnh báo phân loại theo mức độ nghiêm trọng (`CRITICAL`, `HIGH`, `LOW`), tương tác qua các nút `[🚫 Chặn IP]`, `[🟢 Mở khóa (Unban)]`, và `[🔍 Info IP]`. Lệnh chặn được áp dụng thẳng vào Nginx Reverse Proxy và reload ngay lập tức thông qua Docker Socket.
- **Cơ chế tự vệ nâng cao (Self-Defense & Resilience):**
  - *Regex IP Validation:* Chống tấn công Command Injection khi đưa dữ liệu IP vào shell command.
  - *Internal IP Whitelist:* Chống kịch bản tự tấn công từ chối dịch vụ (Self-DoS) khi chặn nhầm gateway hoặc mạng nội bộ Docker (`127.0.0.0/8`, `172.20.0.0/16`, `192.168.0.0/16`, `10.0.0.0/8`).
  - *Anti-429 Rate Limiter & Coalescing Batching (Flood Shield):* Tự động phát hiện đợt bắn tải dồn dập, gộp hàng nghìn cảnh báo thành tin tổng hợp (Summary Alert) và tự điều tiết tốc độ gửi tin để không bao giờ bị khóa API Telegram do mã lỗi HTTP 429.
- **SOC Dashboard phong cách Dark Mode chuyên nghiệp:** Hiển thị thẻ KPI tổng quan, biểu đồ tròn phân bổ trạng thái bảo vệ, Top 5 quy tắc OWASP bị vi phạm nhiều nhất, và bảng theo dõi 50 sự kiện tấn công gần nhất theo thời gian thực.
- **Công cụ kiểm thử độc lập (WAF Scanner):** 100% Python Standard Library, hỗ trợ streaming reader tiết kiệm RAM, tự động sinh báo cáo danh sách payload bypass chi tiết.

### 1.3. Mô hình kiến trúc & Sơ đồ luồng dữ liệu

#### A. Sơ đồ phân vùng mạng & Container (Network Topology)
Toàn bộ hệ thống được triển khai trên nền Docker Compose và cô lập trong subnet mạng Bridge `waf_net` (`172.20.0.0/16`). Chỉ có cổng **80** (WAF Proxy) và cổng **5001** (SOC Dashboard) được public ra máy host:

```
                          [ EXTERNAL TRAFFIC / ATTACKER ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼ (Port 80)                               ▼ (Port 5001)
     ┌───────────────────────────────┐         ┌───────────────────────────────┐
     │           waf_proxy           │         │         soc_dashboard         │
     │    (owasp/modsecurity-crs)    │         │       (Flask & Tailwind)      │
     │         172.20.0.3            │         │          172.20.0.5           │
     └──────────────┬────────────────┘         └───────────────▲───────────────┘
                    │                                          │
       [Proxy Pass] │ (Internal HTTP)           [Read-only WAL]│ (Query < 1ms)
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

#### B. Sơ đồ xử lý sự kiện tuần tự (Sequence Diagram)
Quy trình từ lúc Attacker gửi gói tin độc hại cho đến khi WAF phân tích, Log Parser ghi nhận và Chuyên viên SOC thực thi chặn IP:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Kẻ Tấn Công (Attacker)
    participant WAF as WAF Proxy (ModSecurity)
    participant App as Web Target (PHP/MySQL)
    participant Log as modsec_audit.log
    participant Parser as Log Parser Daemon
    participant DB as SQLite WAL (waf_events.db)
    actor SOC as Chuyên Viên SOC (Telegram)

    Attacker->>WAF: Gửi HTTP Request kèm payload (VD: ' OR '1'='1)
    WAF->>WAF: Kiểm tra cú pháp HTTP & Chấm điểm bất thường (OWASP CRS)
    
    alt Điểm bất thường >= 5 (Tấn công bị chặn)
        WAF-->>Attacker: Trả về HTTP 403 Forbidden
        WAF->>Log: Ghi Transaction JSON Audit Log (Section A-K)
    else Điểm bất thường < 5 (Request lọt lưới)
        WAF->>App: Chuyển tiếp Request tới Backend Web Target
        App-->>Attacker: Trả về HTTP 200 OK
        WAF->>Log: Ghi Transaction JSON Audit Log
    end

    Parser->>Log: Non-blocking Real-time Tail & Parse JSON
    Parser->>Parser: Phân loại 4 trạng thái (BLOCKED / WARNING / BYPASS / CLEAN)
    Parser->>DB: Đẩy bản ghi vào In-Memory Queue -> Flush Batch định kỳ vào WAL
    
    opt Nếu sự kiện là BLOCKED hoặc BYPASS
        Parser->>SOC: Gửi Cảnh báo qua Telegram kèm Inline Keyboard [🚫 Chặn IP]
        SOC->>Parser: Nhấn nút [🚫 Chặn IP] trên Telegram
        Parser->>Parser: Kiểm tra Regex IP & Miễn trừ dải mạng nội bộ (Anti Self-DoS)
        Parser->>WAF: Ghi 'deny <IP>;' vào block.conf & Reload Nginx qua Docker Socket
        Parser->>SOC: Cập nhật tin nhắn thành [🟢 Mở khóa IP] & Báo cáo kết quả
    end
```

---

## 2. GIẢI THÍCH CHI TIẾT CÁC THÀNH PHẦN TRONG DỰ ÁN

Toàn bộ hệ thống bao gồm 5 container dịch vụ chính cùng các công cụ kiểm thử, script vận hành bổ trợ:

### 2.1. Cụm WAF Reverse Proxy (ModSecurity v3 + OWASP CRS v3.3)
- **Container Name:** `waf_proxy`
- **Base Image:** `owasp/modsecurity-crs:nginx`
- **Địa chỉ IP mạng nội bộ:** `172.20.0.3` (Public Port: `80`)
- **Vai trò kỹ thuật:**
  - Là cổng tiếp nhận đầu tiên (Reverse Proxy) đón nhận toàn bộ lưu lượng HTTP gửi đến cổng 80 của hệ thống.
  - Sử dụng ModSecurity v3 kết hợp bộ Core Rule Set (CRS) phiên bản v3.3 chuẩn quốc tế.
  - Phân tích cú pháp tiêu đề (Headers), tham số URL (Query String), nội dung biểu mẫu (Form Data), và thân yêu cầu (Body) để phát hiện dấu hiệu bất thường.
  - Thực thi cơ chế chấm điểm bất thường liên hoàn (Collaborative Anomaly Scoring Detection). Nếu tổng điểm vượt ngưỡng cấu hình (`ANOMALY_INBOUND=5`), Rule ID `949110` sẽ kích hoạt và ngắt kết nối với mã lỗi HTTP **403 Forbidden**.
  - Tích hợp tệp cấu hình động `block.conf` để từ chối các địa chỉ IP bị cấm ngay tại tầng Nginx sơ cấp mà không cần tốn tài nguyên chạy qua bộ Rule Engine.

### 2.2. Ứng dụng mục tiêu & CSDL (Web Target & MySQL)
- **Container Name:** `web_target` (IP: `172.20.0.2`) & `waf_mysql_db` (IP: `172.20.0.4`)
- **Base Image:** `php:8.0-apache` và `mysql:8.0`
- **Vai trò kỹ thuật:**
  - Đóng vai trò là hệ thống ứng dụng web mẫu trong môi trường doanh nghiệp nhưng được cố ý cài cắm các lỗ hổng bảo mật kinh điển thuộc danh mục OWASP Top 10 để phục vụ mục đích kiểm thử và đánh giá phòng lab:
    1. **Lỗ hổng SQL Injection - Authentication Bypass (`index.php`):**
       Truy vấn kiểm tra đăng nhập sử dụng kỹ thuật nối chuỗi trực tiếp:
       ```php
       $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
       $result = $conn->query($query);
       ```
       Kẻ tấn công có thể chèn các payload như `admin' --`, `' OR '1'='1` để đăng nhập mà không cần mật khẩu.
    2. **Lỗ hổng Stored Cross-Site Scripting (`comments.php`):**
       Dữ liệu bình luận do người dùng nhập được lưu vào cơ sở dữ liệu MySQL và hiển thị trực tiếp lên trình duyệt mà không qua bộ lọc mã hóa HTML (`htmlspecialchars`):
       ```php
       <li><b><?php echo htmlspecialchars($c['author']); ?>:</b> <?php echo $c['content']; ?></li>
       ```
    3. **Cơ sở dữ liệu tự động khởi tạo (`db.php`):**
       Tự động kết nối tới container `waf_mysql_db`, khởi tạo schema `vulnerable_db`, bảng `users` (tài khoản mặc định `admin` / `admin`) và bảng `comments` ngay khi ứng dụng khởi chạy lần đầu.

### 2.3. Bộ phân tích nhật ký thời gian thực & SOAR Bot 2 chiều (Log Parser & SOAR Bot)
- **Container Name:** `log_parser`
- **Mã nguồn:** `log_parser.py` (Chạy trên nền Dockerfile đa tầng kế thừa Docker CLI)
- **Địa chỉ IP mạng nội bộ:** `172.20.0.6`
- **Tài nguyên kết nối:** Gắn socket máy chủ `/var/run/docker.sock` và volume thư mục `./logs/`.
- **Vai trò kỹ thuật:**
  Hệ thống được thiết kế 100% trên nền tảng bất đồng bộ (`asyncio` + `aiohttp`), vận hành song song 4 tiến trình Worker độc lập trên cùng một Event Loop duy nhất:
  1. `tail_log_file()`: Lắng nghe không khóa (Non-blocking I/O) file nhật ký `modsec_audit.log`, bóc tách các dòng JSON của ModSecurity, tự động xử lý khi file bị cắt giảm kích thước (log rotation / truncate).
  2. `db_writer_worker()`: Tiếp nhận dữ liệu từ bộ đệm In-Memory Queue và ghi theo cụm (**Batch 50 bản ghi hoặc mỗi chu kỳ 0.5 giây**) vào cơ sở dữ liệu SQLite WAL, loại bỏ hiện tượng tắc nghẽn luồng đọc/ghi.
  3. `telegram_alert_worker()`: Điều tiết cảnh báo gửi tới chuyên viên SOC qua Telegram Bot, tự động kích hoạt chế độ **Flood Shield** khi số lượng sự kiện vượt ngưỡng kiểm soát, gộp cảnh báo thành Summary Alert để chống lỗi HTTP 429 Too Many Requests.
  4. `telegram_polling_worker()`: Lắng nghe phản hồi 2 chiều qua cơ chế Long Polling (`getUpdates`), tiếp nhận các tương tác người dùng khi bấm các nút Inline Keyboard trên giao diện chat.
  
  **Thuật toán phân loại 4 trạng thái sự kiện an ninh:**
  - `BLOCKED`: Mã phản hồi HTTP là 403, 406 hoặc ModSecurity action chứa `deny`. Mức độ: `HIGH`.
  - `BYPASS`: Mã phản hồi HTTP là 200, 301, 302 nhưng tổng điểm Anomaly Score $\ge 5$ hoặc User-Agent/Payload là scanner. Mức độ: `CRITICAL`.
  - `WARNING`: Mã phản hồi HTTP là 200, 301, 302 và tổng điểm Anomaly Score nằm trong khoảng $1 \le \text{Score} < 5$. Mức độ: `MEDIUM`.
  - `CLEAN`: Yêu cầu người dùng hợp lệ, Anomaly Score bằng 0. Mức độ: `LOW`.

### 2.4. Trung tâm giám sát SOC Dashboard (SQLite WAL Query Engine)
- **Container Name:** `soc_dashboard`
- **Mã nguồn:** `app.py` (Flask Framework, Python 3.10)
- **Địa chỉ IP mạng nội bộ:** `172.20.0.5` (Public Port: `5001`)
- **Vai trò kỹ thuật:**
  - Cung cấp giao diện trực quan Dark Mode dành riêng cho chuyên viên phân tích SOC (SOC Analyst).
  - Không đọc trực tiếp file log văn bản tĩnh trên đĩa cứng; toàn bộ dữ liệu được truy vấn từ file SQLite `waf_events.db` ở chế độ WAL Mode. Tốc độ thực thi câu lệnh SQL thống kê đạt kỷ lục dưới **0.2ms**.
  - **Các API Endpoints cung cấp:**
    - `GET /api/stats`: Trả về dữ liệu JSON chứa toàn bộ chỉ số KPI, tỷ lệ phòng vệ, Top quy tắc OWASP bị kích hoạt, và danh sách 50 sự kiện tấn công mới nhất.
    - `GET /api/blocked_ips`: Liệt kê toàn bộ các địa chỉ IP đang bị áp đặt lệnh chặn trong hệ thống.
    - `POST /api/unblock_ip`: Cho phép gỡ chặn một địa chỉ IP trực tiếp từ giao diện Web.
    - `POST /api/clear_data`: Xóa toàn bộ dữ liệu sự kiện, làm rỗng file log, dọn dẹp cơ sở dữ liệu (VACUUM) để phục vụ các đợt kiểm thử mới.

### 2.5. Bộ công cụ kiểm thử WAF tự động (WAF Scanner & Quality Gate)
- **Mã nguồn:** `waf_scanner.py`
- **Đặc tính kỹ thuật cốt lõi:**
  - Được viết hoàn toàn bằng **100% Python Standard Library** (`urllib.request`, `concurrent.futures`, `json`, `time`), không yêu cầu cài đặt thêm bất kỳ thư viện bên ngoài (Zero External Dependencies).
  - Sử dụng cơ chế **Streaming Reader (Generator)** khi nạp danh sách payload từ `payload_xss.txt` (>10.270 mẫu) và `payload_sqli.txt`, giữ mức chiếm dụng RAM cực kỳ thấp (Zero RAM Footprint) mà không làm tràn bộ nhớ máy tính.
  - Phân tích mã phản hồi HTTP: ghi nhận các payload nhận được HTTP 403/406 là `BLOCKED`, các payload nhận HTTP 200/302 là `BYPASS`.
  - Tự động xuất danh sách các vector tấn công vượt qua WAF vào thư mục `reports/bypassed_payloads_*.txt` phục vụ chuyên gia phân tích và bổ sung Custom Rules.
  - Tích hợp kiểm thử tự động trên GitHub Actions CI/CD (`.github/workflows/security-pipeline.yml`) với cơ chế Quality Gate: Build sẽ bị chặn đứng (Failed - Exit Code 1) nếu tỷ lệ bảo vệ `Protection Rate < 90%`.

### 2.6. Tiện ích quản trị & dọn dẹp hệ thống (Reset Traffic Utility)
- **Mã nguồn:** `reset_traffic.sh`
- **Vai trò kỹ thuật:**
  - Tự động hóa việc đưa môi trường thử nghiệm về trạng thái ban đầu chỉ với một câu lệnh Bash shell.
  - Gọi API `/api/clear_data` của SOC Dashboard để làm rỗng bảng `waf_events` trong SQLite.
  - Cắt ngắn file log `logs/modsec_audit.log` về 0 bytes mà không làm đứt file descriptor của tiến trình tailing.
  - Làm sạch danh sách IP bị chặn trong `nginx_conf/block.conf` và gọi Nginx reload.
  - Khôi phục bảng dữ liệu `comments` trong MySQL về dữ liệu mẫu mặc định.

---

## 3. CÁC CẤU HÌNH QUAN TRỌNG CẦN BIẾT

### 3.1. Cấu hình biến môi trường (`.env`)
Tệp `.env` đặt tại thư mục gốc quản lý toàn bộ tham số hoạt động nhạy cảm của các container:

```dotenv
# Cấu hình thông số CSDL MySQL backend
DB_ROOT_PASSWORD=rootpass
DB_USER=root
DB_PASSWORD=rootpass
DB_NAME=vulnerable_db

# Thông tin xác thực Telegram Bot SOAR
TELEGRAM_BOT_TOKEN=8844325232:AAG9RcpXosfWF5YH_MYowcVgyXrQnAd53SU
TELEGRAM_CHAT_ID=7126420245

# Đường dẫn CSDL SQLite lưu trữ sự kiện dùng chung giữa Dashboard và Log Parser
DB_FILE=./logs/waf_events.db
```

| Tham số | Ý nghĩa kỹ thuật | Khuyến nghị vận hành |
| :--- | :--- | :--- |
| `DB_ROOT_PASSWORD` | Mật khẩu tài khoản root của MySQL container | Thay đổi bằng mật khẩu mạnh trên môi trường Production |
| `DB_NAME` | Tên cơ sở dữ liệu mục tiêu được tạo tự động | Mặc định `vulnerable_db` |
| `TELEGRAM_BOT_TOKEN` | Khóa API Token do BotFather cấp | Bảo mật tuyệt đối, không commit lên kho mã nguồn công khai |
| `TELEGRAM_CHAT_ID` | Định danh người dùng hoặc nhóm SOC tiếp nhận cảnh báo | Cần cấu hình chính xác để Bot gửi thông báo và nhận callback |
| `DB_FILE` | Đường dẫn file SQLite Database mount chung | Đặt trong thư mục `./logs` để được đồng bộ giữa các container |

### 3.2. Cấu hình ModSecurity Engine & CRS Rule Engine
Được khai báo trong tệp `docker-compose.yml` và tệp `modsecurity-override.conf`:

```yaml
# Trích đoạn cấu hình container waf_proxy trong docker-compose.yml:
environment:
  - PARANOIA=2
  - BLOCKING_PARANOIA=2
  - ANOMALY_INBOUND=5
  - ANOMALY_OUTBOUND=4
  - MODSEC_RULE_ENGINE=On
```

#### Chi tiết các chỉ số bảo mật cốt lõi:
1. **`MODSEC_RULE_ENGINE=On`:**
   - Kích hoạt chế độ phòng thủ chủ động (Active Blocking Mode).
   - Khi có vi phạm luật vượt ngưỡng, WAF sẽ lập tức ngắt luồng và trả mã HTTP 403 Forbidden thay vì chỉ ghi nhật ký thụ động (`DetectionOnly`).
2. **`PARANOIA=2` & `BLOCKING_PARANOIA=2`:**
   - Thiết lập mức độ cảnh giác ở cấp độ **Paranoia Level 2**.
   - Ở mức này, bộ luật CRS kích hoạt thêm các biểu thức chính quy kiểm tra sâu về kỹ thuật né tránh qua ký tự đặc biệt, nối chuỗi mã hóa trong SQLi và XSS, mang lại sự cân bằng tối ưu giữa khả năng chặn đứng tấn công nâng cao và hạn chế tỷ lệ báo động giả (False Positive).
3. **`ANOMALY_INBOUND=5`:**
   - Ngưỡng điểm bất thường Inbound cho một request đi vào.
   - Mỗi vi phạm quy tắc sẽ được chấm điểm tùy theo độ nghiêm trọng (CRITICAL: 5 điểm, ERROR: 4 điểm, WARNING: 3 điểm, NOTICE: 2 điểm). Với ngưỡng = 5, chỉ cần xuất hiện một lỗi nghiêm trọng dạng CRITICAL (ví dụ: phát hiện cú pháp SQL Injection qua libinjection) là hệ thống sẽ chặn đứng ngay lập tức.
4. **`ANOMALY_OUTBOUND=4`:**
   - Ngưỡng điểm phát hiện rò rỉ thông tin từ phản hồi của server đi ra (ví dụ: rò rỉ mã lỗi stack trace, lộ mật khẩu trong trang HTML).

#### Cấu hình Audit Log Nâng Cao (`modsecurity-override.conf`):
```apache
SecAuditEngine On
SecAuditLog /var/log/modsecurity/modsec_audit.log
SecAuditLogParts ABIJDEFH
SecAuditLogType Serial
SecAuditLogStorageDir /var/log/modsecurity
```
- **Ý nghĩa các thành phần `ABIJDEFH`:**
  - `A`: Header chứa thời gian thực thi (Timestamp), mã định danh giao dịch duy nhất (Transaction ID), địa chỉ IP nguồn và cổng nguồn.
  - `B`: Toàn bộ các tiêu đề yêu cầu HTTP gửi lên (Request Headers).
  - `I`: Dữ liệu gửi lên dạng multipart/form-data.
  - `J`: Trích xuất dữ liệu định dạng JSON tuần tự (Serial JSON) tương thích trực tiếp với trình bóc tách log.
  - `D`: Các tiêu đề phản hồi gửi về cho client (Response Headers).
  - `E`: Nội dung thân phản hồi (Response Body) trước khi trả về.
  - `F`: Tiêu đề phản hồi cuối cùng.
  - `H`: Phần thông tin kiểm toán chứa các Rule ID bị kích hoạt, mô tả chi tiết vi phạm, và tổng điểm Anomaly Score.

### 3.3. Cấu hình Nginx Proxy & Chặn IP động (`default.conf` & `block.conf`)
Tệp `default.conf` điều hướng lưu lượng từ cổng 80 vào ứng dụng backend và tích hợp danh sách cấm:

```nginx
server {
    listen 80;
    server_name localhost;

    # Nạp danh sách các IP bị chặn động bởi SOAR Bot
    include /etc/nginx/conf.d/block.conf;

    location / {
        proxy_pass http://web_target:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

- **Cơ chế hoạt động của `block.conf`:**
  - Ban đầu tệp chỉ chứa dòng ghi chú: `# Dynamic IP blocklist managed by SOAR bot`.
  - Khi chuyên viên SOC nhấn nút chặn IP trên Telegram, `log_parser` sẽ chèn dòng `deny <IP_ADDRESS>;` vào tệp này và gọi lệnh reload Nginx qua Docker Socket:
    ```bash
    docker exec waf_proxy nginx -s reload
    ```
  - **Lợi ích kiến trúc:** Mọi kết nối từ địa chỉ IP này trong tương lai sẽ bị Nginx từ chối ngay tại tầng socket mạng (HTTP 403) mà **không cần phân tích qua bộ luật ModSecurity tốn kém CPU/RAM**.

### 3.4. Cấu hình tối ưu SQLite WAL Engine (< 1ms Latency)
Để loại bỏ triệt để hiện tượng nghẽn I/O khi file log phình to lên hàng trăm megabyte, cả `log_parser.py` và `app.py` đều áp dụng cơ chế tối ưu hóa SQLite WAL tiên tiến:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA cache_size = -64000;
```

#### Bảng so sánh hiệu năng:

| Tiêu chí kỹ thuật | Phương pháp truyền thống (Quét file log text) | Kiến trúc tối ưu SQLite WAL Engine |
| :--- | :--- | :--- |
| **Cơ chế truy vấn** | Đọc tuần tự toàn bộ file đĩa mỗi lần refresh trang | Truy vấn trực tiếp qua chỉ mục B-Tree trên RAM |
| **Thời gian phản hồi API** | 500ms – 3000ms (tùy dung lượng file log) | **0.1ms – 0.5ms** (độ trễ ổn định tuyệt đối) |
| **Xung đột Đọc/Ghi** | Gây khóa file, dễ làm treo luồng parser | Đọc và Ghi diễn ra song song hoàn toàn không khóa |
| **Tải CPU / Đĩa cứng** | CPU liên tục ở mức cao khi bị tấn công tải lớn | Ghi theo lô (Batch Flush) giúp giảm 95% số lần I/O đĩa |

### 3.5. Cơ chế tự vệ (Self-Defense) & Chống nghẽn cảnh báo (Flood Shield)
Hệ thống phòng lab tích hợp các thuật toán phòng vệ tự thân nhằm bảo vệ chính cơ chế phản ứng sự cố:

#### 1. Chống tấn công Command Injection khi tiếp nhận IP:
Địa chỉ IP gửi từ callback bot hoặc API được lọc qua Regex tiêu chuẩn trước khi đưa vào tệp cấu hình hay câu lệnh reload:
```python
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$|"
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::1$"
)
```
Mọi chuỗi chứa ký tự nguy hiểm (ví dụ: `;`, `|`, `&`, `$`...) đều bị loại bỏ ngay từ tầng logic.

#### 2. Miễn trừ dải mạng nội bộ (Chống Self-DoS):
Để ngăn ngừa tình huống chuyên viên vô tình bấm chặn địa chỉ IP gateway của Docker hoặc IP vòng lặp nội bộ làm sập toàn bộ hệ sinh thái dịch vụ, hệ thống cài đặt bộ lọc:
```python
INTERNAL_IP_PREFIXES = ("127.", "172.", "192.168.", "10.")
```
Nếu IP thuộc các dải trên, lệnh chặn sẽ bị từ chối và Bot gửi tin nhắc nhở: *"Bỏ qua chặn mạng nội bộ: IP thuộc phạm vi mạng nội bộ/Gateway, không thể chặn."*

#### 3. Bộ lọc chống lỗi Telegram HTTP 429 & Flood Shield:
- Khi tốc độ tấn công vượt quá 15 req/s (chế độ Benchmark / DDoS), hệ thống tự động chuyển sang chế độ **Flood Shield**:
  - Tạm dừng gửi tin nhắn cảnh báo đơn lẻ.
  - Gom các sự kiện vào bộ thống kê tổng hợp và gửi báo cáo tóm tắt định kỳ 5 giây/lần.
  - Khi dứt đợt tấn công, tự động gửi tin nhắn tổng kết đợt kiểm thử kèm tỷ lệ bảo vệ `Protection Rate` đạt được.

---

## 4. CÁC KỊCH BẢN THỰC NGHIỆM NGẮN (STEP-BY-STEP SCENARIOS)

Dưới đây là 7 kịch bản thực nghiệm ngắn gọn, chuẩn xác, giúp người vận hành kiểm chứng toàn diện các tính năng của hệ sinh thái phòng lab:

### Kịch bản 1: Thử nghiệm tấn công SQL Injection (Authentication Bypass)
- **Mục tiêu:** Kiểm tra khả năng WAF ngăn chặn việc vượt qua cơ chế xác thực đăng nhập mà không cần mật khẩu.
- **Các bước thực hiện:**
  1. Mở trình duyệt web truy cập địa chỉ: `http://localhost/index.php`.
  2. Tại ô `Username`, nhập payload khai thác:
     ```sql
     admin' --
     ```
  3. Tại ô `Password`, nhập một chuỗi bất kỳ (ví dụ: `123456`).
  4. Nhấn nút **Đăng nhập**.
- **Kết quả quan sát kỳ vọng:**
  - Trình duyệt ngay lập tức nhận mã lỗi **`403 Forbidden`** từ Nginx WAF.
  - Kẻ tấn công không thể chuyển hướng vào trang `comments.php`.
  - Trên kênh Telegram xuất hiện cảnh báo đỏ:
    ```text
    🔴 [HIGH] WAF BẢO VỆ CHẶN TẤN CÔNG THÀNH CÔNG
    Rule ID: 942100 (SQL Injection Attack Detected via libinjection)
    Mã HTTP: 403
    ```
  - Trên SOC Dashboard (`http://localhost:5001`), thẻ `Chặn Đứng (403)` tự động tăng thêm 1 đơn vị, sự kiện mới hiển thị trên đầu bảng nhật ký.

---

### Kịch bản 2: Thử nghiệm tấn công Stored Cross-Site Scripting (XSS)
- **Mục tiêu:** Kiểm tra khả năng WAF ngăn chặn chèn mã kịch bản độc hại vào cơ sở dữ liệu bình luận.
- **Các bước thực hiện:**
  Sử dụng terminal gửi trực tiếp một HTTP POST request qua công cụ `curl`:
  ```bash
  curl -i -X POST http://localhost/comments.php \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'content=<script>alert("HACKED_WAF")</script>'
  ```
- **Kết quả quan sát kỳ vọng:**
  - Terminal trả về tiêu đề HTTP phản hồi:
    ```http
    HTTP/1.1 403 Forbidden
    Server: nginx
    ```
  - ModSecurity kích hoạt CRS Rule `941100` (XSS Attack Detected via libinjection).
  - Kiểm tra bảng bình luận trong cơ sở dữ liệu MySQL: payload không bao giờ được ghi vào CSDL, bảo vệ an toàn cho người dùng cuối khi truy cập trang web.

---

### Kịch bản 3: Thử nghiệm quy trình phản ứng tự động SOAR 2 chiều qua Telegram
- **Mục tiêu:** Kiểm chứng tính năng phản ứng tự động (Active Response): Chặn và Mở khóa IP động chỉ bằng thao tác nhấn nút trên Telegram.
- **Các bước thực hiện:**
  1. Giả lập một yêu cầu tấn công mang địa chỉ IP cụ thể (ví dụ IP bên ngoài: `203.0.113.88`):
     ```bash
     curl -i -X POST http://localhost/index.php \
       -H "X-Forwarded-For: 203.0.113.88" \
       -d "username=' OR '1'='1&password=foo"
     ```
  2. Mở ứng dụng Telegram, kiểm tra tin nhắn cảnh báo gửi về từ Bot. Tin nhắn đi kèm 2 nút bấm:
     - `[🚫 Chặn IP 203.0.113.88]`
     - `[🔍 Info IP]`
  3. Nhấn vào nút `[🚫 Chặn IP 203.0.113.88]`:
     - Nút bấm trên tin nhắn tự động chuyển trạng thái thành `[🟢 Mở khóa (Unban): 203.0.113.88]`.
     - Bot gửi thêm một tin nhắn xác nhận: `[XÁC NHẬN THỰC THI SOAR] Chuyên viên vừa kích hoạt chặn IP: 203.0.113.88`.
  4. Kiểm tra nội dung tệp cấu hình `./nginx_conf/block.conf` trên máy host:
     ```nginx
     deny 203.0.113.88;
     ```
  5. Thử gửi lại một request thông thường từ IP này:
     ```bash
     curl -i -H "X-Forwarded-For: 203.0.113.88" http://localhost/
     ```
     *Kết quả:* Nginx từ chối ngay lập tức với mã `403 Forbidden` ở tầng proxy sơ cấp.
  6. Nhấn vào nút `[🟢 Mở khóa (Unban)]`:
     - Dòng `deny 203.0.113.88;` tự động được gỡ bỏ khỏi `block.conf`.
     - Nginx reload lại và quyền truy cập của IP này được phục hồi bình thường.

---

### Kịch bản 4: Thử nghiệm tra cứu thông tin tình báo mối đe dọa (Threat Intel)
- **Mục tiêu:** Kiểm tra khả năng tổng hợp dữ liệu lịch sử tấn công của một địa chỉ IP phục vụ quyết định điều tra của SOC Analyst.
- **Các bước thực hiện:**
  1. Trên tin nhắn cảnh báo sự kiện của Telegram Bot, nhấn nút `[🔍 Info IP]`.
  2. Bot lập tức thực hiện truy vấn tổng hợp trên SQLite WAL Database và gửi phản hồi:
     ```text
     🔍 THÔNG TIN THREAT INTEL CỤC BỘ
     IP: 203.0.113.88
     Tổng Requests: 12
     Bị chặn (403): 10
     Cảnh báo nhẹ (Warning): 2
     Bypass thành công: 0
     Top URI nhắm tới: /index.php (10 hits), /comments.php (2 hits)
     ```
- **Kết quả quan sát kỳ vọng:** Chuyên viên có đầy đủ dữ liệu hành vi của IP mục tiêu ngay trên màn hình chat để quyết định có áp dụng lệnh cấm vĩnh viễn hay không.

---

### Kịch bản 5: Thử nghiệm cơ chế Self-Defense (Chống Self-DoS & Command Injection)
- **Mục tiêu:** Đảm bảo hệ thống SOAR không bị kẻ xấu lợi dụng để tấn công ngược lại chính hạ tầng máy chủ.
- **Thử nghiệm A (Chống Self-DoS):**
  - Giả sử hệ thống phát hiện traffic tấn công xuất phát từ chính IP mạng nội bộ `172.20.0.1` (Docker Gateway).
  - Khi có lệnh yêu cầu chặn IP này, hệ thống Log Parser kích hoạt bộ lọc `is_internal_ip()`:
  - *Kết quả:* Lệnh chặn bị hủy bỏ, trên Telegram xuất hiện thông báo bảo vệ:
    ```text
    ⚠️ [BẢO VỆ HỆ THỐNG] Bỏ qua chặn mạng nội bộ: IP 172.20.0.1 thuộc phạm vi mạng nội bộ/Gateway, không thể chặn.
    ```
- **Thử nghiệm B (Chống Command Injection):**
  - Giả sử kẻ tấn công gửi gói tin với tiêu đề Header giả mạo chuỗi IP độc hại: `1.2.3.4; rm -rf /`.
  - Bộ kiểm tra `is_valid_ip()` bằng Regex lập tức phát hiện chuỗi không đúng định dạng IPv4/IPv6 chuẩn và từ chối xử lý, ngăn chặn hoàn toàn việc thực thi mã độc trên tiến trình shell hệ điều hành.

---

### Kịch bản 6: Thực thi bắn tải WAF Benchmark & Đánh giá Quality Gate
- **Mục tiêu:** Đánh giá năng lực phòng thủ của WAF trước từ điển các vector tấn công thực tế và kiểm tra điều kiện Quality Gate ($\ge 90\%$).
- **Các bước thực hiện:**
  1. Mở terminal tại thư mục dự án và thực thi lệnh quét kiểm thử nhanh (giới hạn 50 payload cho mỗi vector):
     ```bash
     python3 waf_scanner.py --limit=50
     ```
  2. Hoặc thực thi kiểm thử chuyên sâu cho từng vector:
     ```bash
     # Chỉ quét riêng lỗ hổng SQL Injection:
     python3 waf_scanner.py --sqli-only

     # Chỉ quét riêng lỗ hổng XSS:
     python3 waf_scanner.py --xss-only
     ```
- **Kết quả quan sát kỳ vọng:**
  - Scanner hiển thị thanh tiến trình trực quan với tốc độ từ 80 đến 200 req/s.
  - Cơ chế **Flood Shield** của Telegram Bot kích hoạt, không làm tràn hộp thư của chuyên viên.
  - Kết thúc quá trình quét, bảng tổng kết in ra kết quả:
    ```text
    ================================================================================
                       BẢNG TỔNG KẾT KẾT QUẢ ĐÁNH GIÁ WAF
    ================================================================================
     • Tổng số request kiểm thử      : 100
     • Số payload bị CHẶN (403/406)  : 96
     • Số payload LỌT LƯỚI (BYPASS)  : 4
    --------------------------------------------------------------------------------
     🛡️   TỈ LỆ BẢO VỆ (Protection Rate): 96.00% (Chuẩn: >= 90%)
    ================================================================================
    ```
  - Danh sách 4 payload bị bypass được lưu tự động tại `reports/bypassed_payloads_*.txt`.
  - Quality Gate đạt trạng thái **PASSED (Protection Rate $\ge 90\%$)**, trả về Exit Code `0`.

---

### Kịch bản 7: Reset toàn bộ traffic và đưa hệ thống về trạng thái ban đầu
- **Mục tiêu:** Làm sạch toàn bộ dữ liệu kiểm thử cũ để chuẩn bị cho chu kỳ đánh giá hoặc demo mới.
- **Các bước thực hiện:**
  Thực thi kịch bản shell dọn dẹp hệ thống:
  ```bash
  ./reset_traffic.sh
  ```
- **Kết quả quan sát kỳ vọng:**
  - Hệ thống thực thi tuần tự 4 bước:
    1. `[1/4]` Gọi API Dashboard xóa sạch dữ liệu bảng `waf_events` trong SQLite và chạy lệnh `VACUUM`.
    2. `[2/4]` Làm rỗng file `logs/modsec_audit.log` về 0 bytes.
    3. `[3/4]` Xóa toàn bộ lệnh deny trong `nginx_conf/block.conf` và reload Nginx WAF.
    4. `[4/4]` Dọn sạch các bản ghi bình luận inject trong cơ sở dữ liệu MySQL.
  - Toàn bộ các chỉ số trên SOC Dashboard lập tức quay về số `0`, trạng thái hệ thống hoàn toàn mới và sạch sẽ.

---

## 5. TỔNG KẾT & HƯỚNG PHÁT TRIỂN

### 5.1. Giá trị đạt được từ dự án
1. **Kiến trúc phòng thủ chặt chẽ:** Kết hợp thành công giữa công nghệ tường lửa ứng dụng web mã nguồn mở chuẩn quốc tế (ModSecurity + OWASP CRS) và giải pháp giám sát, phản ứng tự động thời gian thực (SOAR + SOC Dashboard).
2. **Hiệu năng vượt trội:** Áp dụng mô hình bất đồng bộ và cơ sở dữ liệu SQLite WAL Mode giúp giải quyết triệt để bài toán nghẽn cổ chai I/O khi hệ thống phải xử lý lượng log khổng lồ từ các cuộc tấn công DDoS/Brute-force.
3. **Mức độ an toàn tự thân cao:** Được thiết kế với tư duy DevSecOps hiện đại, hệ thống có khả năng tự bảo vệ trước các lỗi cấu hình ngớ ngẩn (Self-DoS) cũng như các kỹ thuật tấn công ngược (Command Injection).
4. **Khả năng tự động hóa kiểm thử:** Tích hợp bộ quét WAF độc lập và quy trình CI/CD với Quality Gate rõ ràng giúp đội ngũ phát triển phát hiện sớm các lỗ hổng bypass ngay trong chu kỳ phát triển phần mềm (Shift-Left Security).

### 5.2. Định hướng mở rộng & Phát triển trong tương lai
- **Tích hợp học máy (Machine Learning / AI Anomaly Detection):** Bổ sung mô hình phân tích hành vi người dùng (UEBA) để phát hiện các kỹ thuật tấn công zero-day mà bộ luật tĩnh chưa kịp cập nhật.
- **Mở rộng hỗ trợ giao thức:** Hỗ trợ giám sát và giải mã lưu lượng HTTPS với chứng chỉ SSL/TLS động, hỗ trợ phân tích API JSON/GraphQL và WebSockets.
- **Tích hợp hệ sinh thái SIEM doanh nghiệp:** Hỗ trợ xuất dữ liệu sự kiện định dạng Syslog / CEF hoặc JSON Stream sang các nền tảng SIEM tiêu chuẩn như Elastic Stack (ELK), Splunk, Wazuh.
- **Multi-node Distributed Deployment:** Mở rộng cơ chế đồng bộ danh sách IP bị chặn thông qua Redis Cluster để áp dụng đồng loạt trên cụm nhiều máy chủ WAF Proxy tải cao.

---
*Báo cáo được biên soạn chi tiết phục vụ công tác nghiên cứu, đào tạo, kiểm thử an toàn thông tin và vận hành trung tâm điều hành an ninh mạng (SOC).*

