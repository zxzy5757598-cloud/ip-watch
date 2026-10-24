#!/bin/bash
# ==========================================================================
# ip-watch-listen.sh — Telegram 按需查询监听 (多机共存版)
# 同一个机器人可被多台 VPS 同时监听，互不抢消息：
#   发 "查"            → 所有机器各回一份报告 (标题带机器名)
#   发 "查 香港-DMIT"  → 只有名字被点到的机器回
#   其他消息           → 忽略
# 原理: getUpdates 长轮询只出站、不开监听端口；offset 各机器独立，
#       靠消息内容做客户端过滤。只响应自己的 CHAT_ID；超过 5 分钟的
#       旧消息跳过 (防重启后补发打扰)。
#
# --- 每台 VPS 都装 (VPS 上执行) ---
#   curl -fsSL "脚本直链" -o /usr/local/bin/ip-watch-listen.sh && chmod +x /usr/local/bin/ip-watch-listen.sh
#
# --- 注册为系统服务 (整段复制粘贴) ---
#   sudo tee /etc/systemd/system/ip-watch-listen.service > /dev/null <<'EOF'
#   [Unit]
#   Description=ip-watch Telegram on-demand listener
#   After=network-online.target
#   [Service]
#   ExecStart=/usr/local/bin/ip-watch-listen.sh
#   Restart=always
#   RestartSec=5
#   [Install]
#   WantedBy=multi-user.target
#   EOF
#   sudo systemctl daemon-reload && sudo systemctl enable --now ip-watch-listen.service
#
# --- 验证 ---
#   systemctl is-active ip-watch-listen.service   # 应显示 active
# ==========================================================================
set -u

[ -f /etc/ip-watch.conf ] && source /etc/ip-watch.conf
if [ -z "${TG_TOKEN:-}" ] || [ -z "${CHAT_ID:-}" ]; then
    echo "❌ 未配置 TG_TOKEN / CHAT_ID (/etc/ip-watch.conf)" >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "❌ 需要 python3" >&2; exit 1; }
NODE_NAME="${NODE_NAME:-$(hostname)}"

OFFSET_FILE="/var/lib/ip-watch/tg_offset.txt"
mkdir -p "$(dirname "$OFFSET_FILE")"
OFFSET=0
[ -f "$OFFSET_FILE" ] && OFFSET=$(tr -cd '0-9' < "$OFFSET_FILE")
[ -z "$OFFSET" ] && OFFSET=0

API="https://api.telegram.org/bot${TG_TOKEN}"

while true; do
    NOW_EPOCH=$(date +%s)
    RESP=$(curl -s -m 45 "${API}/getUpdates?timeout=30&offset=${OFFSET}" 2>/dev/null)
    if [ -z "$RESP" ]; then sleep 5; continue; fi

    ACTIONS=$(printf '%s' "$RESP" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for u in d.get("result", []):
    uid = u.get("update_id", 0)
    msg = u.get("message", {}) or {}
    chat = (msg.get("chat", {}) or {}).get("id", "")
    date = msg.get("date", 0)
    text = (msg.get("text", "") or "").strip()
    print("%s|%s|%s|%s" % (uid, chat, date, text.replace("\n", " ")[:60]))
')
    [ -z "$ACTIONS" ] && continue

    while IFS='|' read -r uid chat msgdate text; do
        [ -z "$uid" ] && continue
        OFFSET=$((uid + 1))
        printf '%s' "$OFFSET" > "$OFFSET_FILE"
        # 只响应自己的 CHAT_ID，陌生人消息直接忽略
        [ "$chat" != "$CHAT_ID" ] && continue
        # 跳过 5 分钟前的旧消息 (防服务重启后补发)
        if [ -n "$msgdate" ] && [ "$msgdate" -gt 0 ] 2>/dev/null; then
            AGE=$((NOW_EPOCH - msgdate))
            [ "$AGE" -gt 300 ] && continue
        fi
        # 点名这台，或广播
        MATCH=0
        case "$text" in
            *"$NODE_NAME"*) MATCH=1 ;;
            查|check|状态|报告) MATCH=1 ;;
        esac
        [ "$MATCH" = "1" ] || continue
        curl -s -m 10 -X POST "${API}/sendMessage" \
            -d "chat_id=${CHAT_ID}" \
            --data-urlencode "text=⏳ 收到，正在体检…" >/dev/null 2>&1
        /usr/local/bin/ip-watch.sh --report >/dev/null 2>&1
    done <<< "$ACTIONS"
done
