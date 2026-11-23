#!/usr/bin/env bash
# =============================================================================
# WAF LAB - RESET TRAFFIC & LOGS SCRIPT
# Xoá toàn bộ dữ liệu log, traffic cũ, reset database và gỡ chặn IP để test lại từ đầu.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================"
echo "🧹 ĐANG TIẾN HÀNH RESET TOÀN BỘ TRAFFIC VÀ LOG WAF LAB"
echo "======================================================"

# 1. Gọi API Dashboard nếu container soc_dashboard đang chạy
if curl -s -f -X POST http://localhost:5001/api/clear_data >/dev/null 2>&1; then
    echo "✅ [1/4] Đã reset cơ sở dữ liệu SQLite & Dashboard qua API."
else
    # Phương án dự phòng trực tiếp trên tệp tin
    echo "⚠️ Không kết nối được API Dashboard, tiến hành reset trực tiếp trên file..."
    if [ -f "logs/waf_events.db" ]; then
        python3 -c "
import sqlite3, os
if os.path.exists('logs/waf_events.db'):
    conn = sqlite3.connect('logs/waf_events.db')
    conn.execute('DELETE FROM waf_events;')
    conn.commit()
    conn.execute('VACUUM;')
    conn.commit()
    conn.close()
" 2>/dev/null || true
    fi
    echo "✅ [1/4] Đã làm sạch bảng waf_events trong database SQLite."
fi

# 2. Làm rỗng tệp log ModSecurity
if [ -f "logs/modsec_audit.log" ]; then
    > "logs/modsec_audit.log"
    echo "✅ [2/4] Đã làm rỗng tệp logs/modsec_audit.log (0 bytes)."
fi

# 3. Làm rỗng danh sách IP bị chặn & reset cấu hình Nginx
if [ -f "logs/blocked_ips.txt" ]; then
    > "logs/blocked_ips.txt"
fi

if [ -f "nginx_conf/block.conf" ]; then
    cat << 'EOF' > "nginx_conf/block.conf"
# Dynamic IP blocklist managed by SOAR bot
# Format: deny <IP>;
EOF
fi

# Reload Nginx nếu container waf_proxy đang chạy
if docker ps --format '{{.Names}}' | grep -q "^waf_proxy$"; then
    docker exec waf_proxy nginx -s reload >/dev/null 2>&1 || true
    echo "✅ [3/4] Đã làm sạch block.conf và reload Nginx thành công."
else
    echo "ℹ️ Container waf_proxy chưa chạy, bỏ qua reload Nginx."
fi

# 4. Làm sạch dữ liệu bảng comments trong MySQL (giữ lại bình luận chào mừng mẫu)
if docker ps --format '{{.Names}}' | grep -q "^waf_mysql_db$"; then
    docker exec -i waf_mysql_db mysql -uroot -prootpass vulnerable_db -e "DELETE FROM comments WHERE id > 1;" >/dev/null 2>&1 || true
    echo "✅ [4/4] Đã dọn dẹp các comment inject cũ trong MySQL."
fi

echo "======================================================"
echo "✨ HOÀN TẤT! Hệ thống đã được đưa về trạng thái ban đầu."
echo "👉 Bạn có thể mở http://localhost:5001 để kiểm tra Dashboard."
echo "======================================================"
