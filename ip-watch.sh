#!/bin/bash
# ==========================================================================
# ip-watch.sh — 轻量 VPS IP 体检 + Telegram 告警
# 只做监控，不刷流量、不装常驻服务、不开监听端口。
#
# 监控项: 公网 IP / 国家-城市 / ISP-ASN / proxy&hosting 标记 / Google 区域跳转
#         / 流量统计 (月/日, 需 vnstat) / 线路延迟 (ping 香港/大陆/美国地标)
#         / 流媒体解锁 (YT区域/Netflix/Disney+/TikTok/ChatGPT) / 25端口 / AbuseIPDB
#         / 系统健康 / 监听端口 / DNS劫持 / DNSBL黑名单 / SSH爆破Top10
#         / 安全基线 (SSH配置/fail2ban/防火墙/UID0账户/密钥指纹/cron指纹/高危端口暴露/待更新)
# 策略: 状态变化才告警 (IP 变动、归属地漂移、风控标记变化)；--report 强制发全量报告
#       流量与线路只在日报/按需查询时采集，不参与变化告警判定。
#
# --- 手机一键安装 (VPS 上执行) ---
#   curl -fsSL "脚本直链" -o /usr/local/bin/ip-watch.sh && chmod +x /usr/local/bin/ip-watch.sh
#
# --- 配置 (复制下面整段, 把引号里的内容换成你自己的, 一次粘贴执行) ---
#   sudo tee /etc/ip-watch.conf > /dev/null <<'EOF'
#   TG_TOKEN="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
#   CHAT_ID="123456789"
#   EOF
#
# --- cron (复制整段一次粘贴执行) ---
#   (crontab -l 2>/dev/null; echo '0 */6 * * * /usr/local/bin/ip-watch.sh >/dev/null 2>&1'; echo '0 8 * * * /usr/local/bin/ip-watch.sh --report >/dev/null 2>&1') | crontab -
#
# --- 测试 ---
#   sudo /usr/local/bin/ip-watch.sh --report   # TG 应收到一份日报
#
# Telegram Bot 获取: TG 里找 @BotFather -> /newbot 拿 token;
#   Chat ID: 给 @userinfobot 发任意消息，它会回复你的 ID。
#
# 多台 VPS: 同一个 TG_TOKEN / CHAT_ID 通用，每台在配置里加一行
#   NODE_NAME="香港-DMIT"  (名字自己取，报告里用来区分机器)。
#   EXPECTED_CC="HK"       (期望归属地，用于"原生IP"判定：实际归属=期望 → ✅原生)
#   ABUSEIPDB_KEY="..."    (可选，abuseipdb.com 免费注册拿 key，1000次/天；不填则跳过欺诈分查询)
#   (端口监听改为自动扫描，不再需要 CHECK_PORTS)
# 按需查询监听 (ip-watch-listen.sh) 每台都装；TG 发"查"→所有机器各回一份，
#   发"查 机器名"→只回被点名的那台。
# ==========================================================================
set -u

STATE_FILE="${STATE_FILE:-/var/lib/ip-watch/state.txt}"
REPORT=0
[ "${1:-}" = "--report" ] && REPORT=1

# --- 载入配置 ---
[ -f /etc/ip-watch.conf ] && source /etc/ip-watch.conf
if [ -z "${TG_TOKEN:-}" ] || [ -z "${CHAT_ID:-}" ]; then
    echo "❌ 未配置 TG_TOKEN / CHAT_ID (见脚本头部: /etc/ip-watch.conf)" >&2
    exit 1
fi
NODE_NAME="${NODE_NAME:-$(hostname)}"

log() { echo "[$(date '+%F %T')] $*" >&2; }

# Telegram HTML 模式转义 (& < >)
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# --- 1. 公网 IP ---
PUBLIC_IP=$(curl -4 -s -m 10 https://api.ip.sb/ip 2>/dev/null | tr -d '[:space:]')
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(curl -4 -s -m 10 https://ifconfig.me 2>/dev/null | tr -d '[:space:]')
if [ -z "$PUBLIC_IP" ]; then log "取公网 IP 失败"; exit 1; fi

# --- 2. 地理 + 风控标记 (ip-api.com 免费接口) ---
GEO_JSON=$(curl -s -m 15 "http://ip-api.com/json/${PUBLIC_IP}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting" 2>/dev/null)
if ! printf '%s' "$GEO_JSON" | grep -q '"status":"success"'; then log "ip-api 查询失败"; exit 1; fi

if command -v python3 >/dev/null 2>&1; then
    eval "$(printf '%s' "$GEO_JSON" | python3 -c '
import json, sys, shlex
d = json.load(sys.stdin)
out = {
    "COUNTRY": d.get("country", ""),
    "CC": d.get("countryCode", ""),
    "CITY": ", ".join(x for x in [d.get("city", ""), d.get("regionName", "")] if x),
    "ISP": d.get("isp", "") or d.get("org", ""),
    "ASN": d.get("as", ""),
    "PROXY": "是" if d.get("proxy") else "否",
    "HOSTING": "是" if d.get("hosting") else "否",
}
for k, v in out.items():
    print("%s=%s" % (k, shlex.quote(str(v))))
')"
else
    COUNTRY=$(printf '%s' "$GEO_JSON" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
    CC=""; CITY=$(printf '%s' "$GEO_JSON" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
    ISP=$(printf '%s' "$GEO_JSON" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
    ASN=""; PROXY="未知"; HOSTING="未知"
fi

# --- 2.5 原生 IP 判定 (期望归属地 vs 实际归属地) ---
NATIVE_TXT="➖ 未配置期望区域"
NATIVE_FLAG="-"
if [ -n "${EXPECTED_CC:-}" ]; then
    if [ "${CC}" = "${EXPECTED_CC}" ]; then
        NATIVE_TXT="✅ 原生 (归属 ${CC} = 期望 ${EXPECTED_CC})"
        NATIVE_FLAG="OK"
    elif [ -n "$CC" ]; then
        NATIVE_TXT="⚠️ 漂移！归属 ${CC} ≠ 期望 ${EXPECTED_CC}"
        NATIVE_FLAG="DRIFT"
    fi
fi

# --- 3. Google 区域跳转 ("送中"检测) ---
JUMP_LOC=$(curl -sI -m 10 "http://www.google.com/" 2>/dev/null | grep -i '^location:' | tr -d '\r')
# 备用：有些线路 HEAD 不返回跳转，改用 GET 跟随后的最终 URL
if [ -z "$JUMP_LOC" ]; then
    EFF_URL=$(curl -s -L -o /dev/null -w "%{url_effective}" -m 12 "http://www.google.com/" 2>/dev/null)
    [ -n "$EFF_URL" ] && JUMP_LOC="location: $EFF_URL"
fi
GOOGLE_REGION="未知"
if [ -n "$JUMP_LOC" ]; then
    case "$JUMP_LOC" in
        *".google.cn"*|*"gl=cn"*|*"gl=CN"*) GOOGLE_REGION="CN ⚠️送中" ;;
        *google.com.hk*)  GOOGLE_REGION="HK" ;;
        *google.com.tw*)  GOOGLE_REGION="TW" ;;
        *google.co.jp*)   GOOGLE_REGION="JP" ;;
        *google.com.sg*)  GOOGLE_REGION="SG" ;;
        *google.com*)     GOOGLE_REGION="US" ;;
        *) GL=$(printf '%s' "$JUMP_LOC" | grep -oi 'gl=[a-z][a-z]' | head -1 | cut -d= -f2 | tr 'a-z' 'A-Z')
           [ -n "$GL" ] && GOOGLE_REGION="$GL" ;;
    esac
fi

# --- 3.5 流量与线路 (仅日报/按需查询时采集，不参与变化告警) ---
TRAFFIC_LINE=""
ROUTE_LINE=""
if [ "$REPORT" = "1" ]; then
    DEF_IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    [ -z "$DEF_IFACE" ] && DEF_IFACE="eth0"

    TRAFFIC_LINE=$(python3 - "$DEF_IFACE" <<'PYEOF'
import json, subprocess, sys
iface = sys.argv[1]
def fmt(b):
    try: b = float(b)
    except Exception: return "?"
    for u in ["B","K","M","G","T"]:
        if b < 1024 or u == "T": return "%.1f%s" % (b, u)
        b /= 1024
try:
    raw = subprocess.run(["vnstat","--json"],capture_output=True,text=True,timeout=10).stdout
    d = json.loads(raw)
    ifs = d.get("interfaces",[])
    pick = next((i for i in ifs if i.get("name")==iface), ifs[0] if ifs else None)
    t = (pick or {}).get("traffic",{})
    months = t.get("month",[]) or t.get("months",[])
    days = t.get("day",[]) or t.get("days",[])
    m = months[-1] if months else {}
    dy = days[-1] if days else {}
    mrx, mtx, drx, dtx = m.get("rx",0), m.get("tx",0), dy.get("rx",0), dy.get("tx",0)
    if mrx or mtx or drx or dtx:
        print("📊 本月 ↓%s ↑%s · 今日 ↓%s ↑%s" % (fmt(mrx),fmt(mtx),fmt(drx),fmt(dtx)))
        sys.exit(0)
except Exception:
    pass
try:
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(iface+":"):
                p = line.split(":")[1].split()
                print("📊 网卡累计 ↓%s ↑%s (自开机, 装 vnstat 可看月/日: apt install -y vnstat)" % (fmt(p[0]),fmt(p[8])))
                sys.exit(0)
    print("📊 流量数据不可用")
except Exception:
    print("📊 流量数据不可用")
PYEOF
)

    ping_avg() {
        local avg
        avg=$(ping -4 -c 3 -W 2 -i 0.4 "$1" 2>/dev/null | awk -F/ '/rtt/{print $5}')
        if [ -n "$avg" ]; then printf '%sms' "$avg"; else printf '超时'; fi
    }
    HK_PING=$(ping_avg 1.1.1.1)
    CT_PING=$(ping_avg 114.114.114.114)
    ALI_PING=$(ping_avg 223.5.5.5)
    US_PING=$(ping_avg 8.8.8.8)
    ROUTE_LINE="🛣️ 线路延迟 🇭🇰${HK_PING} · 🇨🇳电信${CT_PING} · 🇨🇳阿里${ALI_PING} · 🇺🇸${US_PING}"
fi

# --- 3.6 流媒体解锁 / 25端口 / 欺诈分 (仅日报/按需查询时采集) ---
STREAM_LINE=""
PORT25_LINE=""
ABUSE_LINE=""
if [ "$REPORT" = "1" ]; then
    UA_WIN="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    # YouTube 区域 (送中直检)
    YT_HTML=$(curl -sL -m 10 -A "$UA_WIN" "https://www.youtube.com/premium" 2>/dev/null)
    YT_CC=$(printf '%s' "$YT_HTML" | grep -Eo '"(contentRegion|countryCode|INNERTUBE_CONTEXT_GL)":"[A-Za-z]{2}"' | head -1 | cut -d'"' -f4 | tr 'a-z' 'A-Z')
    [ -z "$YT_CC" ] && YT_CC="?"
    if [ "$YT_CC" = "CN" ]; then YT_TXT="🔴${YT_CC}送中"; else YT_TXT="🟢${YT_CC}"; fi

    # Netflix / Disney+ / TikTok / ChatGPT (200/3xx 即算可达)
    NF_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 -A "$UA_WIN" "https://www.netflix.com/title/81215567" 2>/dev/null)
    [ "$NF_CODE" = "200" ] && NF_TXT="🟢" || NF_TXT="🔴"
    DP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 -A "$UA_WIN" "https://www.disneyplus.com/" 2>/dev/null)
    [ "$DP_CODE" = "200" ] && DP_TXT="🟢" || DP_TXT="🔴"
    TT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 -A "$UA_WIN" "https://www.tiktok.com/" 2>/dev/null)
    { [ "$TT_CODE" = "200" ] || [ "$TT_CODE" = "301" ]; } && TT_TXT="🟢" || TT_TXT="🔴"
    GPT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 -A "$UA_WIN" "https://chatgpt.com/" 2>/dev/null)
    { [ "$GPT_CODE" = "200" ] || [ "$GPT_CODE" = "301" ] || [ "$GPT_CODE" = "308" ]; } && GPT_TXT="🟢" || GPT_TXT="🔴"
    STREAM_LINE="🎬 流媒体 YT:${YT_TXT} · NF:${NF_TXT} · D+:${DP_TXT} · TT:${TT_TXT} · GPT:${GPT_TXT}"

    # 25 端口出站
    if timeout 6 bash -c 'echo > /dev/tcp/smtp.gmail.com/25' 2>/dev/null; then
        PORT25_LINE="📧 25端口出站：✅ 畅通"
    else
        PORT25_LINE="📧 25端口出站：❌ 被封"
    fi

    # AbuseIPDB 欺诈分 (需自备免费 key)
    if [ -n "${ABUSEIPDB_KEY:-}" ]; then
        ABUSE_JSON=$(curl -s -m 10 -G "https://api.abuseipdb.com/api/v2/check" \
            --data-urlencode "ipAddress=${PUBLIC_IP}" -d maxAgeInDays=90 \
            -H "Key: ${ABUSEIPDB_KEY}" -H "Accept: application/json" 2>/dev/null)
        ABUSE_PARSED=$(printf '%s' "$ABUSE_JSON" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin).get("data", {})
    print("%s|%s" % (d.get("abuseConfidenceScore", "?"), d.get("totalReports", "?")))
except Exception:
    print("?|?")' 2>/dev/null)
        ABUSE_LINE="🛡️ AbuseIPDB 欺诈分：${ABUSE_PARSED%|*} / 被举报 ${ABUSE_PARSED#*|} 次"
    fi
fi

# --- 3.7 系统健康 / 端口存活 / DNS劫持 / 黑名单 (采集快，告警状态用；展示只在日报/按需) ---
# 系统健康
CORES=$(nproc 2>/dev/null || echo 1)
LOAD1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo "?")
MEM_TOT=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)
MEM_AVAIL=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null)
if [ -n "$MEM_TOT" ] && [ -n "$MEM_AVAIL" ] && [ "$MEM_TOT" -gt 0 ] 2>/dev/null; then
    MEM_PCT=$(( (MEM_TOT - MEM_AVAIL) * 100 / MEM_TOT ))
else
    MEM_PCT="?"
fi
DISK_PCT=$(df / 2>/dev/null | awk 'NR==2{sub(/%/,"",$5); print $5}')
UP_DAYS=$(awk '{printf "%d", $1/86400}' /proc/uptime 2>/dev/null || echo "?")
HEALTH_FLAG="OK"; HEALTH_NOTE=""
if [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -ge 90 ] 2>/dev/null; then
    HEALTH_FLAG="WARN"; HEALTH_NOTE="磁盘${DISK_PCT}%"
fi
if awk -v l="${LOAD1}" -v c="$CORES" 'BEGIN{exit !(l+0 > c*2)}' 2>/dev/null; then
    HEALTH_FLAG="WARN"; HEALTH_NOTE="${HEALTH_NOTE:+${HEALTH_NOTE}，}负载${LOAD1}"
fi
SYS_LINE="💻 系统 负载${LOAD1}(${CORES}核) · 内存${MEM_PCT}% · 磁盘${DISK_PCT}% · 在线${UP_DAYS}天"
[ "$HEALTH_FLAG" = "WARN" ] && SYS_LINE="${SYS_LINE} ⚠️${HEALTH_NOTE}"

# 监听端口 (自动扫描本机所有 TCP 监听端口，变化告警)
PORTS_LINE=""; PORTS_FLAG="-"
if command -v ss >/dev/null 2>&1; then
    PORT_LIST=$(ss -tlnp 2>/dev/null | awk 'NR>1 {
        local="";
        for (i=1; i<=NF; i++) { if ($i ~ /:[0-9]+$/) { local=$i; break } }
        if (local == "") next;
        n=split(local,a,":"); port=a[n];
        proc="-";
        if (match($0, /"[^"]+"/)) { proc=substr($0, RSTART+1, RLENGTH-2) }
        if (port != "") print port"("proc")"
    }' | sort -u -t'(' -k1,1n | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$PORT_LIST" ]; then
        # 状态比对只用端口号（进程名 ss 显示有抖动，不参与比对，避免误报）
        PORTS_FLAG=$(printf '%s' "$PORT_LIST" | tr ' ' '\n' | sed 's/(.*//' | sort -un | tr '\n' ' ' | sed 's/ $//')
        PORTS_LINE="🔌 监听端口：${PORT_LIST}"
    fi
fi

# DNS 劫持检测 (假域名应 NXDOMAIN)
DNS_LINE=""; DNS_FLAG="OK"
if getent hosts google.com >/dev/null 2>&1; then
    if getent hosts "nxd-$(date +%s%N).invalid" >/dev/null 2>&1; then DNS_FLAG="HIJACK"; fi
else
    DNS_FLAG="FAIL"
fi
[ "$DNS_FLAG" = "OK" ]     && DNS_LINE="🌐 DNS：✅ 正常"
[ "$DNS_FLAG" = "HIJACK" ] && DNS_LINE="🌐 DNS：⚠️ 疑似劫持（假域名被解析）"
[ "$DNS_FLAG" = "FAIL" ]   && DNS_LINE="🌐 DNS：❌ 解析失败"

# 多源 DNSBL 黑名单
BL_LINE=""; BL_FLAG="-"
if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    BL_HITS=$(python3 - "$PUBLIC_IP" <<'PYEOF'
import socket, sys
socket.setdefaulttimeout(5)
ip = sys.argv[1]
rev = ".".join(reversed(ip.split(".")))
zones = {"Spamhaus": "zen.spamhaus.org", "SpamCop": "bl.spamcop.net",
         "CBL": "cbl.abuseat.org", "PSBL": "psbl.surriel.com"}
hits = []
for name, z in zones.items():
    try:
        socket.gethostbyname(rev + "." + z)
        hits.append(name)
    except Exception:
        pass
print(",".join(hits))
PYEOF
)
    if [ -n "$BL_HITS" ]; then
        BL_FLAG="HIT:${BL_HITS}"; BL_LINE="⛔ 黑名单：⚠️ 命中 ${BL_HITS//,/、}"
    else
        BL_FLAG="CLEAN"; BL_LINE="⛔ 黑名单：✅ 干净 (Spamhaus/SpamCop/CBL/PSBL)"
    fi
fi

# --- 3.8 SSH 安全 (24h 失败登录 Top10 展示；新 IP 成功登录 / 爆破激增才告警) ---
SEC_LINE=""; SEC_FLAG="-"
SEEN_SSH_FILE="/var/lib/ip-watch/seen_ssh_ips.txt"
SSHJ=""
if command -v journalctl >/dev/null 2>&1; then
    SSHJ=$(journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -iE "sshd.*(failed|accepted)")
fi
if [ -z "$SSHJ" ] && [ -f /var/log/auth.log ]; then
    SSHJ=$(grep -ihE "sshd.*(failed|accepted)" /var/log/auth.log 2>/dev/null | tail -3000)
fi
if [ -n "$SSHJ" ]; then
    SEC_FLAG="OK"
    FAIL_TOTAL=$(printf '%s' "$SSHJ" | grep -ci "failed")
    FAIL_TOP=$(printf '%s' "$SSHJ" | grep -i "failed" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -10 | awk '{printf "%s(%s) ", $2, $1}' | sed 's/ $//')
    OK_TOTAL=$(printf '%s' "$SSHJ" | grep -cE "Accepted (password|publickey)")
    OK_IPS=$(printf '%s' "$SSHJ" | grep -E "Accepted (password|publickey)" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//')
    # 新 IP 成功登录检测 (首次运行只建基线不告警)
    SEEN_INIT=0; [ ! -f "$SEEN_SSH_FILE" ] && SEEN_INIT=1
    touch "$SEEN_SSH_FILE"
    NEW_IPS=""
    for ip in $OK_IPS; do
        grep -qx "$ip" "$SEEN_SSH_FILE" 2>/dev/null || { NEW_IPS="${NEW_IPS:+${NEW_IPS} }${ip}"; echo "$ip" >> "$SEEN_SSH_FILE"; }
    done
    [ "$SEEN_INIT" = "1" ] && NEW_IPS=""
    [ -n "$NEW_IPS" ] && SEC_FLAG="NEWLOGIN:${NEW_IPS// /,}"
    if [ "$FAIL_TOTAL" -gt 500 ] && [ "$SEC_FLAG" = "OK" ]; then SEC_FLAG="HIGHFAIL:${FAIL_TOTAL}"; fi
    SEC_LINE="🔐 SSH(24h) 失败${FAIL_TOTAL}次${FAIL_TOP:+ Top:${FAIL_TOP}} | 成功${OK_TOTAL}次${OK_IPS:+ 来自:${OK_IPS}}"
    [ -n "$NEW_IPS" ] && SEC_LINE="${SEC_LINE} ⚠️新IP登录:${NEW_IPS}"
    [ "$SEC_FLAG" != "OK" ] && [ -z "$NEW_IPS" ] && [ "$FAIL_TOTAL" -gt 500 ] && SEC_LINE="${SEC_LINE} ⚠️爆破激增"
else
    SEC_LINE="🔐 SSH：无数据 (sshd 日志不可读)"
fi

# --- 3.9 安全基线 (SSH审计/fail2ban/防火墙/UID0账户/密钥指纹/cron指纹/高危端口/补丁) ---
# SSH 配置审计 (需 root)
SSH_AUDIT_FLAG="-"; SSH_AUDIT_TXT="无权限或未安装"
SSHD_BIN=$(command -v sshd 2>/dev/null)
[ -z "$SSHD_BIN" ] && [ -x /usr/sbin/sshd ] && SSHD_BIN=/usr/sbin/sshd
if [ -n "$SSHD_BIN" ]; then
    SSHD_T=$("$SSHD_BIN" -T 2>/dev/null)
    if [ -n "$SSHD_T" ]; then
        PRL=$(printf '%s' "$SSHD_T" | awk '/^permitrootlogin/{print $2}' | head -1)
        PWA=$(printf '%s' "$SSHD_T" | awk '/^passwordauthentication/{print $2}' | head -1)
        SPT=$(printf '%s' "$SSHD_T" | awk '/^port/{print $2}' | head -1)
        SSH_AUDIT_TXT="root登录=${PRL:-?} 密码登录=${PWA:-?} 端口=${SPT:-?}"
        SSH_AUDIT_FLAG="OK"
        { [ "$PRL" = "yes" ] || [ "$PWA" = "yes" ]; } && SSH_AUDIT_FLAG="RISKY"
    fi
fi

# fail2ban
F2B_FLAG="NOINST"; F2B_TXT="未安装"
if command -v fail2ban-client >/dev/null 2>&1; then
    if fail2ban-client ping 2>/dev/null | grep -q pong; then
        F2B_FLAG="ACTIVE"; F2B_TXT="运行中"
    else
        F2B_FLAG="INACTIVE"; F2B_TXT="已停止"
    fi
fi

# 防火墙
FW_FLAG="-"; FW_TXT="未知"
if command -v ufw >/dev/null 2>&1; then
    case "$(ufw status 2>/dev/null | head -1)" in
        *active*)   FW_FLAG="ON";  FW_TXT="ufw开启" ;;
        *inactive*) FW_FLAG="OFF"; FW_TXT="ufw关闭" ;;
    esac
elif command -v iptables >/dev/null 2>&1; then
    IPT_N=$(iptables -S 2>/dev/null | wc -l)
    if [ "$IPT_N" -le 3 ]; then FW_FLAG="OFF"; FW_TXT="iptables近乎空规则"; else FW_FLAG="ON"; FW_TXT="iptables规则${IPT_N}条"; fi
fi

# UID 0 账户 (正常只有 root)
UID0_USERS=$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
USERS_FLAG="${UID0_USERS:-none}"

# authorized_keys 指纹 (后门钥匙检测)
AK_HASH=$(cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null | grep -v "^#" | grep -v "^$" | sha256sum 2>/dev/null | awk '{print substr($1,1,12)}')
AK_COUNT=$(cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null | grep -c "^ssh-")
AK_FLAG="${AK_HASH:-none}"

# cron 指纹 (持久化后门检测)
CRON_HASH=$( (cat /var/spool/cron/crontabs/* /etc/crontab /etc/cron.d/* 2>/dev/null) | sha256sum 2>/dev/null | awk '{print substr($1,1,12)}')
CRON_FLAG="${CRON_HASH:-none}"

# 高危端口公网暴露
RISKY_PORTS="21 23 3306 5432 6379 27017 5900 11211 9200"
EXPOSED=""
if command -v ss >/dev/null 2>&1; then
    EXPOSED=$(ss -tln 2>/dev/null | awk -v risky="$RISKY_PORTS" 'NR>1 {
        local="";
        for (i=1; i<=NF; i++) { if ($i ~ /:[0-9]+$/) { local=$i; break } }
        if (local == "") next;
        n=split(local,a,":"); port=a[n];
        if (index(" "risky" ", " "port" ") && local ~ /^(\*|0\.0\.0\.0|\[::\]):/) print port
    }' | sort -un | tr '\n' ' ' | sed 's/ $//')
fi
EXP_FLAG="${EXPOSED:-none}"

# 待更新 (Debian 系，只读模拟)
UPD_TXT=""
if command -v apt-get >/dev/null 2>&1; then
    UPD_SIM=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep "^Inst")
    UPD_ALL=$(printf '%s' "$UPD_SIM" | grep -c .)
    UPD_SEC=$(printf '%s' "$UPD_SIM" | grep -ci "security")
    UPD_TXT="待更新${UPD_ALL}(安全${UPD_SEC})"
fi

SEC2_LINE="🛡️ 基线 SSH[${SSH_AUDIT_TXT}]"
[ "$SSH_AUDIT_FLAG" = "RISKY" ] && SEC2_LINE="${SEC2_LINE} ⚠️高风险"
SEC2_LINE="${SEC2_LINE} | fail2ban:${F2B_TXT} | 防火墙:${FW_TXT}
👥 UID0:${UID0_USERS:-无} · 密钥${AK_COUNT:-0}把 · cron指纹${CRON_FLAG}"
[ -n "$EXPOSED" ] && SEC2_LINE="${SEC2_LINE} · ⚠️公网高危端口:${EXPOSED}"
[ -n "$UPD_TXT" ] && SEC2_LINE="${SEC2_LINE} · 📦${UPD_TXT}"

# --- 4. 状态对比 ---
mkdir -p "$(dirname "$STATE_FILE")"
CURRENT_STATE="IP=${PUBLIC_IP} GEO=${COUNTRY}(${CC}) NATIVE=${NATIVE_FLAG} GOOGLE=${GOOGLE_REGION} PROXY=${PROXY} HOSTING=${HOSTING} SYS=${HEALTH_FLAG} PORTS=${PORTS_FLAG} DNS=${DNS_FLAG} BL=${BL_FLAG} SEC=${SEC_FLAG} SSHCFG=${SSH_AUDIT_FLAG} F2B=${F2B_FLAG} FW=${FW_FLAG} UID0=${USERS_FLAG} AK=${AK_FLAG} CRONH=${CRON_FLAG} EXP=${EXP_FLAG}"
OLD_STATE=""; [ -f "$STATE_FILE" ] && OLD_STATE=$(cat "$STATE_FILE")
FIRST_RUN=0; [ ! -f "$STATE_FILE" ] && FIRST_RUN=1

# --- 5. 发送 Telegram ---
tg_send() {
    curl -s -m 15 -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" -d "parse_mode=HTML" \
        --data-urlencode "text=$1" >/dev/null 2>&1
}

NOW=$(date '+%F %T')
E_NODE=$(html_escape "$NODE_NAME")
E_IP=$(html_escape "$PUBLIC_IP")
E_GEO="$(html_escape "$COUNTRY") ($(html_escape "$CC")) $(html_escape "$CITY")"
E_ISP=$(html_escape "$ISP")
E_ASN=$(html_escape "$ASN")
E_GR=$(html_escape "$GOOGLE_REGION")
E_NATIVE=$(html_escape "$NATIVE_TXT")

if [ "$REPORT" = "1" ]; then
    MSG="🛡️ <b>IP 体检日报</b> [${E_NODE}] (${NOW})

🌐 IP: <code>${E_IP}</code>
📍 归属: ${E_GEO}
🏢 ISP: ${E_ISP}
🔢 ${E_ASN}
🔍 Google 区域: ${E_GR}
🎯 ${E_NATIVE}
🚩 Proxy 标记: ${PROXY}
🏠 Hosting 标记: ${HOSTING}
${TRAFFIC_LINE}
${ROUTE_LINE}
${STREAM_LINE}
${PORT25_LINE}
${ABUSE_LINE}
${SYS_LINE}
${PORTS_LINE}
${DNS_LINE}
${BL_LINE}
${SEC_LINE}
${SEC2_LINE}"
    tg_send "$MSG"
    printf '%s' "$CURRENT_STATE" > "$STATE_FILE"
    log "已发送日报"
elif [ "$FIRST_RUN" = "1" ]; then
    printf '%s' "$CURRENT_STATE" > "$STATE_FILE"
    tg_send "✅ <b>ip-watch 已上线</b> [${E_NODE}]
🌐 IP: <code>${E_IP}</code>
📍 ${E_GEO} | Google: ${E_GR}
之后只有 IP/归属地/风控标记变化时才打扰你。"
    log "首次运行，已记录基线"
elif [ "$CURRENT_STATE" != "$OLD_STATE" ]; then
    tg_send "⚠️ <b>IP 状态变化告警</b> [${E_NODE}] (${NOW})

<b>变化前:</b>
<code>$(html_escape "$OLD_STATE")</code>

<b>变化后:</b>
🌐 IP: <code>${E_IP}</code>
📍 归属: ${E_GEO}
🎯 ${E_NATIVE}
🏢 ISP: ${E_ISP}
🔍 Google 区域: ${E_GR}
🚩 Proxy: ${PROXY} / Hosting: ${HOSTING}
${SYS_LINE}
${PORTS_LINE}
${DNS_LINE}
${BL_LINE}
${SEC_LINE}
${SEC2_LINE}"
    printf '%s' "$CURRENT_STATE" > "$STATE_FILE"
    log "状态变化，已告警"
else
    log "无变化，静默"
fi
