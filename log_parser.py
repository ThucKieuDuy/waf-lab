#!/usr/bin/env python3
"""
=============================================================================
WAF MODSECURITY REAL-TIME LOG PARSER & ASYNC 2-WAY TELEGRAM SOAR BOT
=============================================================================
Đặc điểm kỹ thuật:
  - 100% Bất đồng bộ (Asyncio + AIOHTTP)
  - Non-blocking Log Tailing (Không khóa luồng đọc file)
  - Anti-429 Rate Limiter & Coalescing Batching (Chống ngập Telegram API)
  - Telegram Bot 2 chiều (Inline Keyboard [Block IP] & Long Polling Callback)
  - Lưu trữ trực tiếp vào SQLite WAL (Write-Ahead Logging) siêu tốc
=============================================================================
"""

import asyncio
import html
import json
import os
import re
import sqlite3
import subprocess
import time
from typing import Dict, Any, List, Optional
import aiohttp

# ================= KIỂM SOÁT AN TOÀN IP & REGEX =================
# Regex kiểm tra IPv4 chuẩn (0.0.0.0 - 255.255.255.255) và IPv6 cơ bản
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$|"
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::1$"
)

# Danh sách tiền tố IP nội bộ / Docker Gateway cần miễn trừ (Chống Self-DoS)
INTERNAL_IP_PREFIXES = ("127.", "172.", "192.168.", "10.")

def is_valid_ip(ip: str) -> bool:
    """Kiểm tra định dạng IPv4/IPv6 bằng Regex để chống Command Injection."""
    if not ip or not isinstance(ip, str):
        return False
    return bool(IP_REGEX.match(ip.strip()))

def is_internal_ip(ip: str) -> bool:
    """Kiểm tra IP có thuộc dải mạng nội bộ hoặc Docker Gateway để chống Self-DoS."""
    if not ip or not isinstance(ip, str):
        return False
    return ip.strip().startswith(INTERNAL_IP_PREFIXES)


# ================= CẤU HÌNH HỆ THỐNG & TELEGRAM =================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN", "8844325232:AAG9RcpXosfWF5YH_MYowcVgyXrQnAd53SU")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or os.getenv("CHAT_ID", "7126420245")
TELEGRAM_TOKEN = TELEGRAM_BOT_TOKEN
CHAT_ID = TELEGRAM_CHAT_ID

LOG_FILE = os.getenv("LOG_FILE", "./logs/modsec_audit.log")
DB_FILE = os.getenv("DB_FILE", "./logs/waf_events.db")
BLOCKED_IPS_FILE = os.getenv("BLOCKED_IPS_FILE", "./logs/blocked_ips.txt")
NGINX_BLOCK_CONF = os.getenv("NGINX_BLOCK_CONF", "./nginx_conf/block.conf")

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# Hàng đợi bất đồng bộ (In-Memory Async Queues - khởi tạo trong main loop)
db_queue: Optional[asyncio.Queue] = None
alert_queue: Optional[asyncio.Queue] = None

# ================= 1. KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE (WAL MODE) =================
def init_db(db_path: str = DB_FILE) -> None:
    """Khởi tạo SQLite database với cơ chế WAL và chỉ mục tối ưu truy vấn."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0)
    cursor = conn.cursor()
    
    # Kích hoạt WAL (Write-Ahead Logging) và đồng bộ tối ưu
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("PRAGMA synchronous = NORMAL;")
    cursor.execute("PRAGMA busy_timeout = 5000;")
    cursor.execute("PRAGMA cache_size = -64000;")  # 64MB Cache
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        client_ip TEXT,
        method TEXT,
        uri TEXT,
        http_code INTEGER,
        rule_id TEXT,
        rule_msg TEXT,
        rule_label TEXT,
        payload TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_waf_status ON waf_events(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_waf_rule ON waf_events(rule_id, rule_label);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_waf_ip ON waf_events(client_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_waf_id_desc ON waf_events(id DESC);")
    
    conn.commit()
    conn.close()
    print(f"[*] [DATABASE] Đã kích hoạt SQLite WAL Mode tại: {db_path}")

def batch_insert_sync(records: List[tuple], db_path: str = DB_FILE) -> None:
    """Thực thi ghi batch vào SQLite trong thread riêng (không block asyncio loop)."""
    if not records:
        return
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.executemany("""
        INSERT INTO waf_events (timestamp, client_ip, method, uri, http_code, rule_id, rule_msg, rule_label, payload, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] [DATABASE ERROR] Lỗi batch insert ({len(records)} bản ghi): {e}")

async def db_writer_worker() -> None:
    """Worker gom cụm và ghi dữ liệu hàng loạt vào SQLite định kỳ."""
    print("[*] [WORKER] Database Batch Writer Worker đã khởi chạy...")
    batch: List[tuple] = []
    last_flush = time.time()
    
    while True:
        try:
            # Thu thập bản ghi từ queue (timeout 0.2s để flush định kỳ)
            try:
                item = await asyncio.wait_for(db_queue.get(), timeout=0.2)
                batch.append(item)
                db_queue.task_done()
            except asyncio.TimeoutError:
                pass
            
            # Flush vào database nếu gom đủ 50 bản ghi hoặc sau mỗi 0.5s
            now = time.time()
            if batch and (len(batch) >= 50 or (now - last_flush) >= 0.5):
                to_write = list(batch)
                batch.clear()
                last_flush = now
                await asyncio.to_thread(batch_insert_sync, to_write, DB_FILE)
                
        except asyncio.CancelledError:
            if batch:
                await asyncio.to_thread(batch_insert_sync, batch, DB_FILE)
            break
        except Exception as e:
            print(f"[!] Lỗi không mong muốn trong db_writer_worker: {e}")
            await asyncio.sleep(0.5)

# ================= 2. SOAR ACTIVE RESPONSE (XỬ LÝ CHẶN IP) =================
def block_ip(ip_address: str) -> bool:
    """
    Thực thi chặn IP:
    1. Kiểm tra tính hợp lệ bằng Regex và chống chặn nhầm mạng nội bộ (Self-DoS).
    2. Thêm dòng 'deny {ip_address};\n' vào tệp cấu hình ./nginx_conf/block.conf.
    3. Thực thi reload Nginx qua Docker Socket: docker exec waf_proxy nginx -s reload.
    """
    ip_address = ip_address.strip()

    # 1. Kiểm tra tính hợp lệ bằng Regex (Chống Command Injection)
    if not is_valid_ip(ip_address):
        print(f"[!] [SECURITY ALERT] IP không hợp lệ, từ chối thực thi: {ip_address}")
        return False

    # 2. Kiểm tra IP nội bộ / Gateway (Chống Self-DoS)
    if is_internal_ip(ip_address):
        print(f"[!] [SELF-DOS PROTECTION] Bỏ qua chặn mạng nội bộ: {ip_address}")
        return False

    try:
        conf_path = os.getenv("NGINX_BLOCK_CONF", "./nginx_conf/block.conf")
        os.makedirs(os.path.dirname(os.path.abspath(conf_path)), exist_ok=True)

        deny_line = f"deny {ip_address};\n"
        existing_lines = []
        if os.path.exists(conf_path):
            with open(conf_path, "r", encoding="utf-8") as f:
                existing_lines = f.readlines()

        if deny_line not in existing_lines:
            with open(conf_path, "a", encoding="utf-8") as f:
                f.write(deny_line)

        # Cập nhật danh sách lưu trữ blocked_ips.txt cho Dashboard & tra cứu
        os.makedirs(os.path.dirname(os.path.abspath(BLOCKED_IPS_FILE)), exist_ok=True)
        with open(BLOCKED_IPS_FILE, "a+", encoding="utf-8") as f:
            f.seek(0)
            existing = {line.strip() for line in f if line.strip()}
            if ip_address not in existing:
                f.write(f"{ip_address}\n")

        # Reload Nginx qua Docker Socket
        subprocess.run(["docker", "exec", "waf_proxy", "nginx", "-s", "reload"], check=True)

        print(f"\n[🛡️ SOC ACTION] >>> ĐÃ CHẶN IP THÀNH CÔNG: {ip_address} (Nginx Deny & Reload) <<<")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi reload Nginx: {e}")
        return False
    except Exception as e:
        print(f"[!] Lỗi khi thực thi block IP {ip_address}: {e}")
        return False

async def execute_block_ip(client_ip: str) -> bool:
    """Wrapper bất đồng bộ cho block_ip."""
    return await asyncio.to_thread(block_ip, client_ip)

def unblock_ip(ip_address: str) -> bool:
    """
    Thực thi gỡ cấm (Unban) IP:
    1. Xóa dòng 'deny {ip_address};' khỏi tệp cấu hình ./nginx_conf/block.conf.
    2. Cập nhật file blocked_ips.txt.
    3. Thực thi reload Nginx qua Docker Socket: docker exec waf_proxy nginx -s reload.
    """
    ip_address = ip_address.strip()

    if not is_valid_ip(ip_address):
        print(f"[!] [SECURITY ALERT] IP không hợp lệ, từ chối mở khóa: {ip_address}")
        return False

    try:
        conf_path = os.getenv("NGINX_BLOCK_CONF", "./nginx_conf/block.conf")
        if os.path.exists(conf_path):
            with open(conf_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if f"deny {ip_address};" not in l]
            with open(conf_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

        # Xóa khỏi danh sách blocked_ips.txt
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and l.strip() != ip_address]
            with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
                for ip in lines:
                    f.write(f"{ip}\n")

        # Reload Nginx qua Docker Socket
        subprocess.run(["docker", "exec", "waf_proxy", "nginx", "-s", "reload"], check=True)

        print(f"\n[🔓 SOC ACTION] >>> ĐÃ MỞ KHÓA (UNBAN) IP THÀNH CÔNG: {ip_address} (Nginx Reload) <<<")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi reload Nginx khi unblock: {e}")
        return False
    except Exception as e:
        print(f"[!] Lỗi khi mở khóa IP {ip_address}: {e}")
        return False

async def execute_unblock_ip(client_ip: str) -> bool:
    """Wrapper bất đồng bộ cho unblock_ip."""
    return await asyncio.to_thread(unblock_ip, client_ip)

def query_ip_threat_info(client_ip: str) -> str:
    """Truy vấn thông tin thống kê về IP từ SQLite để gửi báo cáo phản hồi nhanh."""
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
            SUM(CASE WHEN status = 'BYPASS' THEN 1 ELSE 0 END) as bypassed,
            SUM(CASE WHEN status = 'WARNING' THEN 1 ELSE 0 END) as warnings
        FROM waf_events WHERE client_ip = ?
        """, (client_ip,))
        row = cursor.fetchone()
        
        cursor.execute("""
        SELECT uri, COUNT(*) as c FROM waf_events 
        WHERE client_ip = ? GROUP BY uri ORDER BY c DESC LIMIT 3
        """, (client_ip,))
        top_uris = cursor.fetchall()
        conn.close()
        
        total = row[0] or 0
        blocked = row[1] or 0
        bypassed = row[2] or 0
        warnings = row[3] or 0
        
        uri_str = ", ".join([f"<code>{u[0]}</code> ({u[1]} hits)" for u in top_uris]) or "N/A"
        
        return (
            f"🔍 <b>THÔNG TIN THREAT INTEL CỤC BỘ</b>\n"
            f"<b>IP:</b> <code>{client_ip}</code>\n"
            f"<b>Tổng Requests:</b> {total}\n"
            f"<b>Bị chặn (403):</b> {blocked}\n"
            f"<b>Cảnh báo nhẹ (Warning):</b> {warnings}\n"
            f"<b>Bypass thành công:</b> {bypassed}\n"
            f"<b>Top URI nhắm tới:</b> {uri_str}"
        )
    except Exception as e:
        return f"Lỗi truy vấn dữ liệu IP: {e}"

# ================= 3. TELEGRAM ALERT WORKER (CHỐNG LỖI 429 & BATCHING) =================
async def send_telegram_async(session: aiohttp.ClientSession, payload: Dict[str, Any]) -> bool:
    """Gửi HTTP request bất đồng bộ tới Telegram với cơ chế Auto-Retry khi dính 429."""
    url = f"{TELEGRAM_API_URL}/sendMessage"
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                data = await resp.json()
                
                # Thành công
                if resp.status == 200 and data.get("ok"):
                    return True
                
                # Xử lý Telegram Rate Limit (HTTP 429 Too Many Requests)
                if resp.status == 429:
                    retry_after = data.get("parameters", {}).get("retry_after", 3)
                    print(f"[⚠️ WARNING 429] Telegram yêu cầu đợi {retry_after}s. Đang tạm dừng bất đồng bộ...")
                    await asyncio.sleep(retry_after + 0.5)
                    continue
                
                print(f"[!] Telegram API trả về lỗi {resp.status}: {data.get('description')}")
                return False
                
        except asyncio.TimeoutError:
            print(f"[!] Timeout khi gửi Telegram (Thử lại {attempt+1}/{max_retries})...")
            await asyncio.sleep(1.0)
        except Exception as e:
            print(f"[!] Lỗi kết nối Telegram API: {e}")
            await asyncio.sleep(1.0)
            
    return False

async def telegram_alert_worker(session: aiohttp.ClientSession) -> None:
    """
    Worker gửi cảnh báo Telegram tích hợp Flood Shield & Benchmark Aggregator:
    - Chế độ thường: Gửi từng cảnh báo kèm Inline Button (tối đa 1 tin/giây).
    - Chế độ Flood / Benchmark (khi queue >= 8): Tự động kích hoạt Flood Shield,
      gom cụm toàn bộ cảnh báo trong hàng đợi và chỉ gửi 1 tin tổng hợp mỗi 15-20s.
    - Tuyệt đối chống nghẽn Telegram API (Anti-429) và chống tràn RAM.
    """
    print("[*] [WORKER] Telegram Alert Dispatcher (Flood Shield Enabled) đã khởi chạy...")
    flood_mode = False
    flood_stats = {"total": 0, "blocked": 0, "bypassed": 0, "ips": set()}
    last_flood_alert_time = 0.0
    
    while True:
        try:
            alert = await alert_queue.get()
            q_size = alert_queue.qsize()
            
            # NẾU PHÁT HIỆN TẤN CÔNG TẢI CAO / BENCHMARK (Queue >= 8 hoặc đang trong Flood Mode)
            if q_size >= 8 or flood_mode:
                if not flood_mode:
                    flood_mode = True
                    flood_stats = {"total": 0, "blocked": 0, "bypassed": 0, "ips": set()}
                    last_flood_alert_time = time.time()
                    print("[⚡ FLOOD SHIELD] Phát hiện đợt tấn công quy mô lớn / Benchmark. Đã kích hoạt Flood Shield Telegram!")
                
                # Gom cụm toàn bộ các cảnh báo đang chờ trong Queue
                batch_alerts = [alert]
                while not alert_queue.empty():
                    try:
                        extra_alert = alert_queue.get_nowait()
                        batch_alerts.append(extra_alert)
                        alert_queue.task_done()
                    except asyncio.QueueEmpty:
                        break
                alert_queue.task_done()
                
                # Cập nhật thống kê tích lũy
                for a in batch_alerts:
                    flood_stats["total"] += 1
                    flood_stats["ips"].add(a.get("ip", "Unknown"))
                    if a.get("level") == "CRITICAL":
                        flood_stats["bypassed"] += 1
                    else:
                        flood_stats["blocked"] += 1
                
                now = time.time()
                # Chỉ gửi tin nhắn Telegram định kỳ mỗi 15 giây để không bị phạt 429
                if (now - last_flood_alert_time) >= 15.0:
                    last_flood_alert_time = now
                    total_f = flood_stats["total"]
                    blk_f = flood_stats["blocked"]
                    byp_f = flood_stats["bypassed"]
                    rate_f = (blk_f / total_f * 100) if total_f > 0 else 100.0
                    escaped_ips = ', '.join([f'<code>{html.escape(str(ip))}</code>' for ip in list(flood_stats["ips"])[:5]])
                    
                    msg_text = (
                        f"⚡ <b>[FLOOD SHIELD] BÁO CÁO TIẾN TRÌNH BENCHMARK / STRESS TEST</b>\n"
                        f"<b>------------------------------------</b>\n"
                        f"<b>Tổng số requests đã nhận:</b> <b>{total_f}</b>\n"
                        f"<b>Chặn đứng (403):</b> <b>{blk_f}</b>\n"
                        f"<b>Bypass lọt lưới (200):</b> <b>{byp_f}</b>\n"
                        f"<b>Tỉ lệ bảo vệ (Protection Rate):</b> <b>{rate_f:.2f}%</b>\n"
                        f"<b>Top IPs:</b> {escaped_ips}\n"
                        f"<b>------------------------------------</b>\n"
                        f"<i>(Hệ thống tự động gom báo cáo 15s/lần để chống tràn Telegram API)</i>"
                    )
                    
                    first_ip = list(flood_stats["ips"])[0] if flood_stats["ips"] else "127.0.0.1"
                    inline_keyboard = {
                        "inline_keyboard": [
                            [{"text": f"🚫 Chặn IP ({first_ip})", "callback_data": f"block:{first_ip}"}]
                        ]
                    }
                    payload = {
                        "chat_id": CHAT_ID,
                        "text": msg_text,
                        "parse_mode": "HTML",
                        "reply_markup": inline_keyboard
                    }
                    await send_telegram_async(session, payload)
                
                # Nếu hàng đợi đã cạn, kiểm tra nếu sau 8s không có thêm attack thì thoát Flood Mode
                if alert_queue.empty():
                    await asyncio.sleep(2.0)
                    if alert_queue.empty() and flood_mode:
                        # Gửi tin nhắn kết thúc đợt kiểm thử
                        total_f = flood_stats["total"]
                        blk_f = flood_stats["blocked"]
                        byp_f = flood_stats["bypassed"]
                        rate_f = (blk_f / total_f * 100) if total_f > 0 else 100.0
                        msg_text = (
                            f"✅ <b>[BENCHMARK HOÀN TẤT] KẾT QUẢ ĐỢT KIỂM THỬ TẢI CAO</b>\n"
                            f"<b>------------------------------------</b>\n"
                            f"<b>Tổng số payload kiểm tra:</b> <b>{total_f}</b>\n"
                            f"<b>Số payload bị WAF CHẶN (403):</b> <b>{blk_f}</b>\n"
                            f"<b>Số payload BYPASS (200):</b> <b>{byp_f}</b>\n"
                            f"<b>Tỉ lệ bảo vệ đạt được:</b> <b>{rate_f:.2f}%</b>\n"
                            f"<b>------------------------------------</b>\n"
                            f"<i>Lưu lượng đã trở lại bình thường. Flood Shield đã tắt.</i>"
                        )
                        payload = {"chat_id": CHAT_ID, "text": msg_text, "parse_mode": "HTML"}
                        await send_telegram_async(session, payload)
                        flood_mode = False
                        flood_stats = {"total": 0, "blocked": 0, "bypassed": 0, "ips": set()}
                
                continue
            
            # CẢNH BÁO ĐƠN LẺ THÔNG THƯỜNG (KHI LƯU LƯỢNG BÌNH THƯỜNG)
            level = alert["level"]
            client_ip = alert["ip"]
            uri = alert["uri"]
            http_code = alert["http_code"]
            rule_id = alert["rule_id"]
            rule_msg = alert["rule_msg"]
            payload_str = alert.get("payload", "-")
            
            if level == "CRITICAL":
                header = "🚨 <b>[CRITICAL] CẢNH BÁO TẤN CÔNG VƯỢT WAF THÀNH CÔNG!</b>"
            elif level == "HIGH":
                header = "🔴 <b>[HIGH] WAF BẢO VỆ CHẶN TẤN CÔNG THÀNH CÔNG</b>"
            else:
                header = "🔵 <b>[LOW] PHÁT HIỆN YÊU CẦU BẤT THƯỜNG</b>"
            
            escaped_payload = html.escape(str(payload_str)[:60])
            escaped_ip = html.escape(str(client_ip))
            escaped_uri = html.escape(str(uri))
            escaped_rule_id = html.escape(str(rule_id))
            escaped_rule_msg = html.escape(str(rule_msg))

            msg_text = (
                f"{header}\n"
                f"<b>------------------------------------</b>\n"
                f"<b>Mức độ:</b> {level}\n"
                f"<b>IP Nguồn:</b> <code>{escaped_ip}</code>\n"
                f"<b>URI:</b> <code>{escaped_uri}</code>\n"
                f"<b>Mã HTTP:</b> <code>{http_code}</code>\n"
                f"<b>Rule ID:</b> <code>{escaped_rule_id}</code>\n"
                f"<b>Chi tiết:</b> {escaped_rule_msg}\n"
                f"<b>Payload:</b> <code>{escaped_payload}</code>\n"
                f"<b>------------------------------------</b>"
            )
            
            inline_keyboard = {
                "inline_keyboard": [
                    [
                        {"text": f"🚫 Chặn IP {client_ip}", "callback_data": f"block:{client_ip}"},
                        {"text": "🔍 Info IP", "callback_data": f"info:{client_ip}"}
                    ]
                ]
            }
            
            payload = {
                "chat_id": CHAT_ID,
                "text": msg_text,
                "parse_mode": "HTML",
                "reply_markup": inline_keyboard
            }
            
            await send_telegram_async(session, payload)
            alert_queue.task_done()
            await asyncio.sleep(1.0)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[!] Lỗi trong telegram_alert_worker: {e}")
            await asyncio.sleep(1.0)

# ================= 4. TELEGRAM 2-WAY BOT LISTENER (XỬ LÝ NÚT BẤM CALLBACK) =================
async def telegram_polling_worker(session: aiohttp.ClientSession) -> None:
    """
    Worker lắng nghe tương tác 2 chiều từ người dùng (Long Polling getUpdates):
    - Nhận sự kiện khi bấm nút [ 🚫 Block IP ] hoặc [ 🔍 Info IP ].
    - Gọi API answerCallbackQuery và cập nhật lại giao diện tin nhắn.
    """
    print("[*] [WORKER] Telegram 2-Way Bot Polling Worker đã kích hoạt...")
    offset = 0
    
    while True:
        try:
            url = f"{TELEGRAM_API_URL}/getUpdates"
            params = {"offset": offset, "timeout": 20}
            
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=25)) as resp:
                if resp.status != 200:
                    await asyncio.sleep(3.0)
                    continue
                
                res_data = await resp.json()
                if not res_data.get("ok"):
                    await asyncio.sleep(3.0)
                    continue
                
                updates = res_data.get("result", [])
                for update in updates:
                    offset = update["update_id"] + 1
                    
                    # Bắt sự kiện người dùng bấm Inline Button
                    callback_query = update.get("callback_query")
                    if not callback_query:
                        continue
                    
                    query_id = callback_query["id"]
                    cb_data = callback_query.get("data", "")
                    from_user = callback_query.get("from", {}).get("first_name", "Admin")
                    msg = callback_query.get("message", {})
                    chat_id = msg.get("chat", {}).get("id")
                    message_id = msg.get("message_id")
                    
                    # 1. Xử lý nút [ 🚫 Block IP ]
                    if cb_data.startswith("block_") or cb_data.startswith("block:"):
                        target_ip = (cb_data.split("_", 1)[1] if "block_" in cb_data else cb_data.split(":", 1)[1]).strip()
                        
                        # KIỂM TRA 1: Validate regex IP (Chống Command Injection)
                        if not is_valid_ip(target_ip):
                            await session.post(f"{TELEGRAM_API_URL}/answerCallbackQuery", json={
                                "callback_query_id": query_id,
                                "text": "Lỗi: Địa chỉ IP không hợp lệ!",
                                "show_alert": True
                            })
                            continue

                        # KIỂM TRA 2: Kiểm tra dải mạng nội bộ (Chống Self-DoS)
                        if is_internal_ip(target_ip):
                            # Phản hồi popup cảnh báo
                            await session.post(f"{TELEGRAM_API_URL}/answerCallbackQuery", json={
                                "callback_query_id": query_id,
                                "text": "Bỏ qua chặn mạng nội bộ",
                                "show_alert": False
                            })
                            # Gửi tin nhắn thông báo bỏ qua chặn mạng nội bộ
                            if chat_id:
                                await session.post(f"{TELEGRAM_API_URL}/sendMessage", json={
                                    "chat_id": chat_id,
                                    "text": f"⚠️ <b>[BẢO VỆ HỆ THỐNG]</b> Bỏ qua chặn mạng nội bộ: IP <code>{html.escape(target_ip)}</code> thuộc phạm vi mạng nội bộ/Gateway, không thể chặn.",
                                    "parse_mode": "HTML"
                                })
                            continue

                        # Phản hồi tức thì popup Telegram (Xóa vòng xoay loading)
                        await session.post(f"{TELEGRAM_API_URL}/answerCallbackQuery", json={
                            "callback_query_id": query_id,
                            "text": f"Đang thực thi chặn IP {target_ip} trên WAF...",
                            "show_alert": False
                        })
                        
                        # Thực thi chặn IP trên Nginx container
                        success = await execute_block_ip(target_ip)
                        
                        if success and chat_id and message_id:
                            # Cập nhật Inline Button trên tin nhắn cũ thành [ 🟢 Mở khóa IP ]
                            await session.post(f"{TELEGRAM_API_URL}/editMessageReplyMarkup", json={
                                "chat_id": chat_id,
                                "message_id": message_id,
                                "reply_markup": {
                                    "inline_keyboard": [
                                        [
                                            {"text": f"🟢 Mở khóa (Unban): {target_ip}", "callback_data": f"unban_{target_ip}"},
                                            {"text": "🔍 Info IP", "callback_data": f"info_{target_ip}"}
                                        ]
                                    ]
                                }
                            })
                            
                            # Gửi tin nhắn xác nhận
                            confirm_text = (
                                f"🛡️ <b>[XÁC NHẬN THỰC THI SOAR]</b>\n"
                                f"Chuyên viên <b>{html.escape(from_user)}</b> vừa kích hoạt chặn IP: <code>{html.escape(target_ip)}</code>.\n"
                                f"Trạng thái: <b>THÀNH CÔNG</b>. Đã cập nhật <code>deny {html.escape(target_ip)};</code> vào Nginx WAF và reload."
                            )
                            await session.post(f"{TELEGRAM_API_URL}/sendMessage", json={
                                "chat_id": chat_id,
                                "text": confirm_text,
                                "parse_mode": "HTML"
                            })

                    # 2. Xử lý nút [ 🟢 Mở khóa (Unban) ]
                    elif cb_data.startswith("unban_") or cb_data.startswith("unblock:"):
                        target_ip = cb_data.split("_", 1)[1] if "unban_" in cb_data else cb_data.split(":", 1)[1]
                        
                        await session.post(f"{TELEGRAM_API_URL}/answerCallbackQuery", json={
                            "callback_query_id": query_id,
                            "text": f"Đang gỡ chặn IP {target_ip}...",
                            "show_alert": False
                        })
                        
                        success = await execute_unblock_ip(target_ip)
                        
                        if success and chat_id and message_id:
                            # Cập nhật Inline Button lại thành [ 🚫 Chặn lại IP ]
                            await session.post(f"{TELEGRAM_API_URL}/editMessageReplyMarkup", json={
                                "chat_id": chat_id,
                                "message_id": message_id,
                                "reply_markup": {
                                    "inline_keyboard": [
                                        [
                                            {"text": f"🚫 Chặn lại IP {target_ip}", "callback_data": f"block_{target_ip}"},
                                            {"text": "🔍 Info IP", "callback_data": f"info_{target_ip}"}
                                        ]
                                    ]
                                }
                            })
                            
                            unban_text = (
                                f"🔓 <b>[XÁC NHẬN UNBAN SOAR]</b>\n"
                                f"Chuyên viên <b>{html.escape(from_user)}</b> vừa gỡ cấm IP: <code>{html.escape(target_ip)}</code>.\n"
                                f"Trạng thái: <b>ĐÃ MỞ KHÓA</b>. Đã xóa dòng deny khỏi Nginx WAF và reload."
                            )
                            await session.post(f"{TELEGRAM_API_URL}/sendMessage", json={
                                "chat_id": chat_id,
                                "text": unban_text,
                                "parse_mode": "HTML"
                            })
                    
                    # 3. Xử lý nút [ 🔍 Info IP ]
                    elif cb_data.startswith("info_") or cb_data.startswith("info:"):
                        target_ip = cb_data.split("_", 1)[1] if "info_" in cb_data else cb_data.split(":", 1)[1]
                        await session.post(f"{TELEGRAM_API_URL}/answerCallbackQuery", json={
                            "callback_query_id": query_id,
                            "text": "Đang tra cứu Threat Intel...",
                            "show_alert": False
                        })
                        
                        intel_text = query_ip_threat_info(target_ip)
                        await session.post(f"{TELEGRAM_API_URL}/sendMessage", json={
                            "chat_id": chat_id,
                            "text": intel_text,
                            "parse_mode": "HTML"
                        })
                        
        except asyncio.CancelledError:
            break
        except Exception as e:
            # Bắt toàn bộ ngoại lệ để worker không bao giờ bị dừng
            print(f"[!] Lỗi kết nối polling Telegram: {e}")
            await asyncio.sleep(3.0)

# ================= 5. NON-BLOCKING REAL-TIME LOG TAILING =================
def parse_modsec_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Phân tích 1 dòng JSON từ ModSecurity Serial Audit Log theo 4 trạng thái chuẩn:
      - BLOCKED: HTTP status 403/406 hoặc ModSecurity action chứa 'deny'.
      - WARNING: HTTP status 200/301/302, có kích hoạt rule phụ (Total score > 0 nhưng < 5).
      - BYPASS:  HTTP status 200/301/302 VÀ (Total score >= 5 HOẶC User-Agent/Headers là scanner).
      - CLEAN:   HTTP status 200/301/302 với 0 điểm anomaly score.
    """
    try:
        data = json.loads(line)
        tx = data.get("transaction", {})
        
        client_ip = tx.get("client_ip", "Unknown")
        timestamp = tx.get("time_stamp", "")
        req = tx.get("request", {})
        uri = req.get("uri", "/")
        method = req.get("method", "GET")
        headers = req.get("headers", {})
        resp = tx.get("response", {})
        http_code = resp.get("http_code", 0)
        messages = tx.get("messages", [])
        action = str(tx.get("action", "")).lower()
        total_anomaly_score = 0
        rule_id = "N/A"
        rule_msg = "Clean Request"
        matched_data = "-"
        
        # 1. Trích xuất User-Agent và kiểm tra dấu hiệu công cụ tấn công / Security Scanner
        user_agent = ""
        if isinstance(headers, dict):
            user_agent = next((str(v) for k, v in headers.items() if k.lower() == "user-agent"), "")
        elif isinstance(headers, list):
            for h in headers:
                if isinstance(h, (list, tuple)) and len(h) >= 2 and str(h[0]).lower() == "user-agent":
                    user_agent = str(h[1])
                    break
                elif isinstance(h, dict) and h.get("name", "").lower() == "user-agent":
                    user_agent = str(h.get("value", ""))
                    break

        ua_lower = user_agent.lower()
        headers_str = str(headers).lower()

        # Nhận diện các security scanner chuyên dụng: GoTestWAF, Nikto, Nuclei, sqlmap, acunetix
        dedicated_scanners = ["gotestwaf", "nikto", "nuclei", "sqlmap", "acunetix", "nmap"]
        is_scanner = any(sig in ua_lower or sig in headers_str for sig in dedicated_scanners)

        # Với curl: coi là attack test tool nếu có điểm anomaly > 0 hoặc URI/query chứa pattern đáng ngờ
        if "curl" in ua_lower:
            attack_patterns = ["<", ">", "script", "alert", "select", "union", "1=1", "' or '", "../", "passwd", "%3c", "%3e"]
            has_suspicious_payload = any(p in uri.lower() for p in attack_patterns)
            if total_anomaly_score > 0 or has_suspicious_payload:
                is_scanner = True

        # 2. Tính toán Total Anomaly Score và bóc tách thông tin Rule vi phạm
        # (tiếp tục quét messages)

        # Kiểm tra xem có rule tổng 949110/959100 ghi rõ tổng điểm anomaly hay không
        for msg in messages:
            details = msg.get("details", {})
            r_id = str(details.get("ruleId", ""))
            msg_text = msg.get("message", "")
            match_data = str(details.get("data", ""))

            # CRS Rule 949110 ghi: "Inbound Anomaly Score Exceeded (Total Score: X...)"
            m = re.search(r"Total (?:Anomaly )?Score:\s*(\d+)", msg_text + " " + match_data, re.IGNORECASE)
            if m:
                total_anomaly_score = max(total_anomaly_score, int(m.group(1)))

            # Lấy thông tin rule vi phạm đại diện (bỏ qua rule tổng 949110 / 959100)
            if r_id and r_id not in ["949110", "959100"] and rule_id == "N/A":
                rule_id = r_id
                rule_msg = msg.get("message", "Rule Violation")
                matched_data = details.get("data", "Payload detected")

        # Nếu không có rule 949110 (do score < 5 chưa chạm ngưỡng chặn), tính tổng điểm từ các rule con
        if total_anomaly_score == 0 and messages:
            calculated_score = 0
            for msg in messages:
                details = msg.get("details", {})
                r_id = str(details.get("ruleId", ""))
                if r_id in ["949110", "959100", "980130"]:
                    continue
                sev = str(details.get("severity", ""))
                # Bảng điểm chuẩn CRS theo severity
                if sev == "2":      # CRITICAL
                    calculated_score += 5
                elif sev == "3":    # ERROR
                    calculated_score += 4
                elif sev == "4":    # WARNING
                    calculated_score += 3
                elif sev == "5":    # NOTICE
                    calculated_score += 2
                else:
                    calculated_score += 3
            total_anomaly_score = calculated_score

        rule_label = f"{rule_id} ({rule_msg[:25]}...)" if rule_id != "N/A" else None

        # 3. Phân loại 4 trạng thái theo yêu cầu: BLOCKED, WARNING, BYPASS, CLEAN
        is_blocked = (http_code in [403, 406]) or ("deny" in action)

        if is_blocked:
            status = "BLOCKED"
            level = "HIGH"
        elif http_code in [200, 301, 302]:
            if total_anomaly_score >= 5 or is_scanner:
                status = "BYPASS"
                level = "CRITICAL"
                if rule_msg == "Clean Request":
                    rule_msg = "Security Scanner Attack Bypassed WAF"
                    matched_data = f"Scanner [{user_agent[:40]}]"
            elif total_anomaly_score > 0:
                status = "WARNING"
                level = "MEDIUM"
            else:
                status = "CLEAN"
                level = "LOW"
        else:
            # Các HTTP status khác (ví dụ: 404, 500)
            if total_anomaly_score >= 5 or is_scanner:
                status = "BYPASS"
                level = "CRITICAL"
            elif total_anomaly_score > 0:
                status = "WARNING"
                level = "MEDIUM"
            else:
                status = "CLEAN"
                level = "LOW"

        db_tuple = (timestamp, client_ip, method, uri, http_code, rule_id, rule_msg, rule_label, matched_data, status)

        # Chỉ tạo cảnh báo Telegram cho các cuộc tấn công thực sự (BLOCKED hoặc BYPASS)
        # Các request WARNING và CLEAN không gửi chuông báo động để chống Alert Fatigue
        alert_obj = None
        if status in ["BLOCKED", "BYPASS"]:
            alert_obj = {
                "level": level,
                "ip": client_ip,
                "uri": uri,
                "http_code": http_code,
                "rule_id": rule_id,
                "rule_msg": rule_msg,
                "payload": matched_data
            }

        return {"db_record": db_tuple, "alert": alert_obj}

    except json.JSONDecodeError:
        return None
    except Exception as e:
        print(f"[!] Lỗi phân tích cú pháp dòng log: {e}")
        return None

async def tail_log_file() -> None:
    """Đọc file log ModSecurity thời gian thực không làm khóa event loop."""
    print(f"[*] [TAIL] Bắt đầu lắng nghe log ModSecurity tại: {LOG_FILE}")
    
    # Đợi file log xuất hiện nếu container vừa mới bật
    while not os.path.exists(LOG_FILE):
        print(f"[*] Đang chờ file log {LOG_FILE} được tạo bởi WAF...")
        await asyncio.sleep(2.0)
        
    # Mở file với chế độ thay thế lỗi ký tự để tránh UnicodeDecodeError với các payload dị dạng
    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        # Bắt đầu đọc từ cuối file (hoặc từ đầu nếu file nhỏ)
        f.seek(0, os.SEEK_END)
        current_size = os.path.getsize(LOG_FILE)
        
        while True:
            line = f.readline()
            if not line:
                # Kiểm tra file rotation (khi log bị xoay hoặc truncate)
                try:
                    new_size = os.path.getsize(LOG_FILE)
                    if new_size < current_size:
                        print("[*] Phát hiện file log bị xoay vòng (Truncate/Rotate). Đang tải lại con trỏ...")
                        f.seek(0, os.SEEK_SET)
                    current_size = new_size
                except Exception:
                    pass
                
                # Trả quyền điều khiển cho Event Loop trong 0.15s (Non-blocking I/O)
                await asyncio.sleep(0.15)
                continue
            
            line_str = line.strip()
            if not (line_str.startswith("{") and line_str.endswith("}")):
                continue
            
            parsed = parse_modsec_line(line_str)
            if not parsed:
                continue
            
            # Đẩy bản ghi vào Queue ghi SQLite
            if parsed["db_record"]:
                await db_queue.put(parsed["db_record"])
            
            if parsed["alert"]:
                try:
                    alert_queue.put_nowait(parsed["alert"])
                except asyncio.QueueFull:
                    pass

async def reload_watcher_worker() -> None:
    """Lắng nghe tín hiệu reload Nginx thông qua file cờ .nginx_reload."""
    log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
    reload_flag = os.path.join(log_dir, ".nginx_reload")
    while True:
        try:
            if os.path.exists(reload_flag):
                try:
                    os.remove(reload_flag)
                except Exception:
                    pass
                print("[*] [RELOAD WATCHER] Nhận tín hiệu reload Nginx...")
                try:
                    res = subprocess.run(["docker", "exec", "waf_proxy", "nginx", "-s", "reload"], capture_output=True, text=True)
                    if res.returncode == 0:
                        print("[+] [RELOAD WATCHER] Reload Nginx thành công!")
                    else:
                        print(f"[!] [RELOAD WATCHER] Lỗi reload: {res.stderr.strip()}")
                except Exception as ex:
                    print(f"[!] [RELOAD WATCHER] Lỗi thực thi: {ex}")
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)

# ================= 6. HÀM CHÍNH KHỞI ĐỘNG HỆ THỐNG =================
async def main() -> None:
    global db_queue, alert_queue
    db_queue = asyncio.Queue()
    alert_queue = asyncio.Queue(maxsize=1000)

    print("=" * 70)
    print("  WAF MODSECURITY ADVANCED ASYNC LOG PARSER & 2-WAY TELEGRAM BOT")
    print("=" * 70)
    
    # 1. Khởi tạo Database SQLite WAL
    init_db(DB_FILE)
    
    # 2. Khởi tạo HTTP Client Session dùng chung cho mọi tác vụ mạng
    async with aiohttp.ClientSession() as session:
        # Chạy đồng thời các tác vụ bất đồng bộ độc lập
        tasks = [
            asyncio.create_task(db_writer_worker()),
            asyncio.create_task(telegram_alert_worker(session)),
            asyncio.create_task(telegram_polling_worker(session)),
            asyncio.create_task(tail_log_file()),
            asyncio.create_task(reload_watcher_worker()),
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            print("[*] Đang dừng hệ thống an toàn...")
        finally:
            for t in tasks:
                t.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[+] Đã dừng WAF Parser & Telegram Bot.")
