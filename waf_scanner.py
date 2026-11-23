#!/usr/bin/env python3
"""
=============================================================================
WAF AUTOMATED SECURITY SCANNER (UNIFIED SCANNER)
(100% PYTHON STANDARD LIBRARY - ZERO EXTERNAL DEPENDENCIES)
=============================================================================
Đặc điểm kỹ thuật:
  - Tự động nạp và quét từ 2 tệp:
      + payload_xss.txt  -> Nhắm vào mục tiêu XSS (POST comments.php field 'content')
      + payload_sqli.txt -> Nhắm vào mục tiêu SQLi (POST index.php field 'username')
  - Tự động bỏ qua nếu tệp không tồn tại mà không gây lỗi.
  - 100% Thư viện tiêu chuẩn Python (urllib, concurrent.futures, json, time).
  - Không tốn RAM (Streaming Reader), không làm đơ máy, không spam Telegram API.
  - Đầu ra tinh gọn: CHỈ IN RA BẢNG KẾT QUẢ VÀ DANH SÁCH CÁC PAYLOAD ĐÃ BYPASS.
=============================================================================
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Cấu hình màu hiển thị Console
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def find_file(filenames: List[str]) -> Optional[str]:
    """Tìm tệp theo danh sách tên ưu tiên (case-insensitive)."""
    for fname in filenames:
        if os.path.exists(fname):
            return fname
    return None


def count_lines(filepath: str, limit: int = 0) -> int:
    """Đếm số payload hợp lệ trong tệp."""
    c = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                c += 1
                if 0 < limit <= c:
                    return limit
    return c


def stream_payloads(filepath: str, limit: int = 0):
    """Bộ tạo đọc từng dòng payload (Zero RAM Footprint)."""
    c = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            yield s
            c += 1
            if 0 < limit <= c:
                break


def test_payload(
    attack_type: str,
    payload: str,
    target_url: str,
    post_data_dict: Dict[str, str],
    delay: float
) -> Dict[str, Any]:
    """Gửi payload đến WAF và phân loại mã trạng thái HTTP."""
    if delay > 0:
        time.sleep(delay)

    try:
        encoded_data = urllib.parse.urlencode(post_data_dict).encode("utf-8")
        req = urllib.request.Request(
            target_url,
            data=encoded_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "WAF-Unified-Scanner/3.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            code = resp.getcode()
            return {"type": attack_type, "status": code, "payload": payload}

    except urllib.error.HTTPError as e:
        return {"type": attack_type, "status": e.code, "payload": payload}
    except Exception:
        return {"type": attack_type, "status": 999, "payload": payload}


def run_scan_phase(
    phase_name: str,
    filepath: str,
    target_url: str,
    target_field: str,
    extra_fields: Dict[str, str],
    workers: int,
    delay: float,
    limit: int
) -> Tuple[Dict[str, int], List[Dict[str, str]]]:
    """Thực thi quét một bộ testcase."""
    total = count_lines(filepath, limit)
    if total == 0:
        return {"total": 0, "blocked": 0, "bypassed": 0, "malformed": 0, "errors": 0}, []

    print(f"\n{BOLD}{CYAN}>>> Đang quét {phase_name}:{RESET} {BOLD}{filepath}{RESET} ({total:,} payloads) -> {target_url}")

    stats = {"total": 0, "blocked": 0, "bypassed": 0, "malformed": 0, "errors": 0}
    bypassed_items: List[Dict[str, str]] = []

    start_time = time.time()
    bar_width = 25

    with ThreadPoolExecutor(max_workers=workers) as executor:
        gen = stream_payloads(filepath, limit)
        futures = set()

        # Nạp trước số lượng tác vụ vừa đủ
        for _ in range(workers * 4):
            try:
                p = next(gen)
                data = {target_field: p}
                data.update(extra_fields)
                futures.add(executor.submit(test_payload, phase_name, p, target_url, data, delay))
            except StopIteration:
                break

        while futures:
            done = []
            for f in list(futures):
                if f.done():
                    done.append(f)
                    futures.remove(f)

            if not done:
                time.sleep(0.01)
                continue

            for f in done:
                res = f.result()
                status = res["status"]
                p = res["payload"]
                stats["total"] += 1

                if status in [403, 406]:
                    stats["blocked"] += 1
                elif status in [200, 301, 302]:
                    stats["bypassed"] += 1
                    bypassed_items.append({"type": phase_name, "payload": p, "status": str(status)})
                elif status in [400, 404]:
                    stats["malformed"] += 1
                else:
                    stats["errors"] += 1

                try:
                    next_p = next(gen)
                    data = {target_field: next_p}
                    data.update(extra_fields)
                    futures.add(executor.submit(test_payload, phase_name, next_p, target_url, data, delay))
                except StopIteration:
                    pass

            # Cập nhật thanh tiến trình trên 1 dòng
            sent = stats["total"]
            percent = (sent / total * 100) if total > 0 else 0.0
            filled = int(bar_width * sent / total) if total > 0 else 0
            bar = "█" * filled + "░" * (bar_width - filled)
            elapsed = time.time() - start_time
            rps = sent / elapsed if elapsed > 0 else 0.0

            sys.stdout.write(
                f"\r{CYAN}[{bar}] {sent:,}/{total:,} ({percent:.1f}%){RESET} | "
                f"{GREEN}🛡️ Chặn: {stats['blocked']:,}{RESET} | "
                f"{RED}⚠️ Bypass: {stats['bypassed']:,}{RESET} | "
                f"{YELLOW}⚡ {rps:.1f} req/s{RESET}"
            )
            sys.stdout.flush()

    sys.stdout.write("\r" + " " * 95 + "\r")
    sys.stdout.flush()
    return stats, bypassed_items


def main():
    parser = argparse.ArgumentParser(
        description="Công cụ quét kiểm thử WAF duy nhất từ payload_xss.txt và payload_sqli.txt"
    )
    parser.add_argument("--xss-file", default=None, help="Đường dẫn file XSS (Mặc định: tự tìm payload_xss.txt / payload_XSS.txt)")
    parser.add_argument("--sqli-file", default=None, help="Đường dẫn file SQLi (Mặc định: tự tìm payload_sqli.txt / payload_SQLi.txt)")
    parser.add_argument("--xss-only", action="store_true", help="Chỉ quét lỗ hổng XSS")
    parser.add_argument("--sqli-only", action="store_true", help="Chỉ quét lỗ hổng SQL Injection")
    parser.add_argument("--workers", type=int, default=8, help="Số luồng gửi đồng thời (Mặc định: 8 luồng)")
    parser.add_argument("--delay", type=float, default=0.02, help="Độ trễ nghỉ giữa các request (Mặc định: 0.02s)")
    parser.add_argument("--limit", type=int, default=0, help="Giới hạn số payload kiểm thử mỗi loại (0 = toàn bộ)")
    parser.add_argument("--xss-url", default="http://localhost:80/comments.php", help="URL mục tiêu XSS")
    parser.add_argument("--sqli-url", default="http://localhost:80/index.php", help="URL mục tiêu SQLi")

    args = parser.parse_args()

    # Xác định tệp payload XSS
    xss_file = args.xss_file or find_file(["payload_xss.txt", "payload_XSS.txt"])
    # Xác định tệp payload SQLi
    sqli_file = args.sqli_file or find_file(["payload_sqli.txt", "payload_SQLi.txt"])

    print(f"\n{BOLD}{CYAN}============================================================================={RESET}")
    print(f"{BOLD}         WAF UNIFIED SCANNER (XSS & SQL INJECTION BENCHMARK){RESET}")
    print(f"{BOLD}{CYAN}============================================================================={RESET}")
    print(f" • File XSS          : {BOLD}{xss_file if xss_file else 'Không tìm thấy (Bỏ qua)'}{RESET}")
    print(f" • File SQLi         : {BOLD}{sqli_file if sqli_file else 'Không tìm thấy (Bỏ qua)'}{RESET}")
    print(f" • Cấu hình tốc độ   : {BOLD}{args.workers} workers, delay {args.delay}s{RESET} (Chống quá tải RAM & Telegram)")
    print(f" • Chế độ in kết quả : {BOLD}CHỈ IN DANH SÁCH PAYLOAD ĐÃ VƯỢT QUA WAF (BYPASS){RESET}")
    print(f"{CYAN}-----------------------------------------------------------------------------{RESET}")

    all_bypassed: List[Dict[str, str]] = []
    total_stats = {"total": 0, "blocked": 0, "bypassed": 0, "malformed": 0, "errors": 0}

    # 1. Quét SQL Injection nếu có
    if not args.xss_only:
        if sqli_file:
            s_stats, s_bypassed = run_scan_phase(
                "SQLi", sqli_file, args.sqli_url, "username", {"password": "testpassword"},
                args.workers, args.delay, args.limit
            )
            for k in total_stats:
                total_stats[k] += s_stats[k]
            all_bypassed.extend(s_bypassed)
        else:
            print(f"\n{YELLOW}[*] Không phát hiện tệp payload_sqli.txt -> Bỏ qua kiểm thử SQLi.{RESET}")

    # 2. Quét XSS nếu có
    if not args.sqli_only:
        if xss_file:
            x_stats, x_bypassed = run_scan_phase(
                "XSS", xss_file, args.xss_url, "content", {},
                args.workers, args.delay, args.limit
            )
            for k in total_stats:
                total_stats[k] += x_stats[k]
            all_bypassed.extend(x_bypassed)
        else:
            print(f"\n{YELLOW}[*] Không phát hiện tệp payload_xss.txt -> Bỏ qua kiểm thử XSS.{RESET}")

    # 3. Tính toán chỉ số bảo mật tổng thể
    total_sent = total_stats["total"]
    blocked = total_stats["blocked"]
    bypassed = total_stats["bypassed"]
    malformed = total_stats["malformed"]
    resolved = blocked + bypassed
    prot_rate = (blocked / resolved * 100) if resolved > 0 else 100.0

    print("\n" + "=" * 80)
    print(f"                  {BOLD}BẢNG TỔNG KẾT KẾT QUẢ ĐÁNH GIÁ WAF{RESET}")
    print("=" * 80)
    print(f" • Tổng số request kiểm thử      : {BOLD}{total_sent:,}{RESET}")
    print(f" • Số payload bị CHẶN (403/406)  : {GREEN}{BOLD}{blocked:,}{RESET}")
    print(f" • Số payload Malformed (400)    : {YELLOW}{malformed:,}{RESET}")
    print(f" • Số payload LỌT LƯỚI (BYPASS)  : {RED}{BOLD}{bypassed:,}{RESET}")
    print("-" * 80)
    print(f" 🛡️  {BOLD}TỈ LỆ BẢO VỆ (Protection Rate): {GREEN if prot_rate >= 90 else RED}{prot_rate:.2f}%{RESET} (Chuẩn: >= 90%)")
    print("=" * 80)

    # 4. CHỈ IN RA DANH SÁCH PAYLOAD ĐÃ BYPASS
    if not all_bypassed:
        print(f"\n{GREEN}{BOLD}[✓] HOÀN TOÀN AN TOÀN! KHÔNG CÓ BẤT KỲ PAYLOAD NÀO VƯỢT QUA ĐƯỢC WAF.{RESET}\n")
    else:
        print(f"\n{RED}{BOLD}╔═════════════════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{RED}{BOLD}║         DANH SÁCH CÁC PAYLOAD ĐÃ VƯỢT QUA WAF (BYPASS THÀNH CÔNG)           ║{RESET}")
        print(f"{RED}{BOLD}╚═════════════════════════════════════════════════════════════════════════════╝{RESET}")
        print(f"{YELLOW}* Tìm thấy {len(all_bypassed):,} payload lọt lưới (Mã HTTP 200/302):{RESET}\n")

        for idx, item in enumerate(all_bypassed, 1):
            t = item["type"]
            p = item["payload"]
            color = RED if t == "SQLi" else YELLOW
            print(f"{BOLD}[{idx:03d}] [{color}{t}{RESET}{BOLD}]{RESET} {p}")

        # Lưu danh sách này vào tệp reports để tiện tra cứu
        os.makedirs("reports", exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        out_txt = f"reports/bypassed_payloads_{ts}.txt"
        with open(out_txt, "w", encoding="utf-8") as f:
            for item in all_bypassed:
                f.write(f"[{item['type']}] {item['payload']}\n")
        print(f"\n[*] Danh sách chi tiết các payload bypass đã được xuất ra: {BOLD}{out_txt}{RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Đã tạm dừng quét theo yêu cầu.{RESET}")
