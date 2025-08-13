#!/usr/bin/env bash
# deploy_monitoring_stack.sh
set -euo pipefail

# ========== styling ==========
green(){ printf "\033[1;32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[1;33m%s\033[0m\n" "$*"; }
red(){ printf "\033[1;31m%s\033[0m\n" "$*"; }
info(){ printf "[-] %s\n" "$*"; }
ok(){ green "[OK] $*"; }
warn(){ yellow "[WARN] $*"; }
err(){ red "[ERR] $*"; }

# ========== preflight ==========
command -v docker >/dev/null || { err "docker belum terpasang. Arch: sudo pacman -S docker && sudo systemctl enable --now docker"; exit 1; }
docker version >/dev/null || { err "docker tidak berjalan"; exit 1; }

# ========== paths ==========
ROOT="$(pwd)"
mkdir -p caddy cloudflared streamlit/app suricata frontend/src backend/app

backup_if_exists(){ [ -e "$1" ] && mv "$1" "$1.bak_$(date +%Y%m%d_%H%M%S)" && warn "backup: $1 -> $1.bak_*" || true; }

# ========== .env ==========
touch .env
# pastikan kunci wajib ada: TOKEN (cloudflared), SURI_IFACE (default wlan0), COOKIE_SECRET (random)
if ! grep -q '^SURI_IFACE=' .env; then echo "SURI_IFACE=wlan0" >> .env; ok "SURI_IFACE=wlan0 (default) ditambahkan ke .env"; fi
if ! grep -q '^COOKIE_SECRET=' .env; then
  COOKIE_SECRET="$(head -c 32 /dev/urandom | base64)"
  echo "COOKIE_SECRET=${COOKIE_SECRET}" >> .env
  ok "COOKIE_SECRET dibuat & ditambahkan ke .env"
fi
if ! grep -q '^TOKEN=' .env; then
  warn "Variabel TOKEN (cloudflared tunnel token) belum ada di .env."
  warn "Tambah manual: echo 'TOKEN=<isi-token-kamu>' >> .env"
fi

# ========== Caddyfile ==========
if [ ! -f caddy/Caddyfile ]; then
  cat > caddy/Caddyfile <<'CADDY'
{
  auto_https off
  servers :80 { protocols h1 h2c }
}

:80 {
  # API & Auth -> Tornado
  handle_path /api/*    { reverse_proxy tornado-web:8080 }
  handle_path /login*   { reverse_proxy tornado-web:8080 }
  handle_path /logout*  { reverse_proxy tornado-web:8080 }

  # Gate Streamlit /monitor dengan cookie "session"
  @authed header_regexp hasSess Cookie session=.+

  handle /monitor* {
    handle @authed {
      uri strip_prefix /monitor
      reverse_proxy streamlit-app:8501
    }
    handle { redir /login?next=/monitor 302 }
  }

  # Static React (hasil build)
  root * /srv/www
  encode zstd gzip
  try_files {path} /index.html
  file_server
}
CADDY
  ok "caddy/Caddyfile dibuat"
else
  ok "caddy/Caddyfile ditemukan (tidak ditimpa)"
fi

# ========== BACKEND (Tornado login) ==========
# kalau user sudah punya backend sendiri, kita hanya siapkan Dockerfile;
# kalau file app/main.py belum ada, kita buatkan login minimal (fox/bebek).
if [ ! -f backend/Dockerfile ]; then
  cat > backend/Dockerfile <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
# Kalau ada requirements.txt, pakai itu; kalau tidak, minimal tornado
COPY app /app/app
RUN set -eux; \
    if [ -f /app/app/requirements.txt ]; then \
      pip install --no-cache-dir -r /app/app/requirements.txt; \
    else \
      pip install --no-cache-dir tornado==6.4.1; \
    fi
EXPOSE 8080
CMD ["python", "-m", "app.main"]
DOCKER
  ok "backend/Dockerfile dibuat"
fi

if [ ! -f backend/app/main.py ]; then
  cat > backend/app/main.py <<'PY'
import os, urllib.parse
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, authenticated

COOKIE_SECRET = os.getenv("COOKIE_SECRET","dev")
LOGIN_URL = "/login"
USERS = {"fox":"foxzie900","bebek":"bebekcantik321"}

HTML_LOGIN = """<!doctype html><html><head><meta charset="utf-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#0b1020;color:#e6f;display:flex;align-items:center;justify-content:center;height:100vh}
form{background:#11193a;padding:24px;border-radius:12px;min-width:300px}
input{width:100%;margin:.5rem 0;padding:.6rem;border-radius:8px;border:1px solid #334}
button{width:100%;padding:.7rem;border:0;border-radius:8px;background:#6cf;color:#012;font-weight:700}
.msg{color:#faa;margin-bottom:.6rem}</style></head><body>
<form method="post" action="/login"><h2>🔐 Monitoring Login</h2>{msg}
<input type="hidden" name="next" value="{next}">
<input name="username" placeholder="username" required>
<input name="password" type="password" placeholder="password" required>
<button type="submit">Login</button></form></body></html>"""

class Base(RequestHandler):
    def get_current_user(self):
        u=self.get_secure_cookie("session"); return u.decode() if u else None

class Login(Base):
    def get(self):
        nxt=self.get_query_argument("next","/"); msg=self.get_query_argument("msg","")
        self.write(HTML_LOGIN.format(msg=f'<div class="msg">{msg}</div>' if msg else "", next=nxt))
    def post(self):
        u=self.get_body_argument("username","").strip()
        p=self.get_body_argument("password","").strip()
        nxt=self.get_body_argument("next","/").strip() or "/"
        if USERS.get(u)==p:
            self.set_secure_cookie("session",u,httponly=True,samesite="lax"); self.redirect(nxt)
        else:
            q=urllib.parse.urlencode({"next":nxt,"msg":"Invalid credentials"}); self.redirect(f"/login?{q}")

class Logout(Base):
    def get(self): self.clear_cookie("session"); self.redirect("/login")

class Health(RequestHandler):
    def get(self): self.write({"ok":True})

class Hello(Base):
    @authenticated
    def get(self): self.write({"hello": self.current_user})

def make_app():
    return Application([
        (r"/login",Login),(r"/logout",Logout),
        (r"/api/health",Health),(r"/api/hello",Hello),
    ], cookie_secret=COOKIE_SECRET, login_url=LOGIN_URL, xsrf_cookies=False)

if __name__=="__main__":
    app=make_app(); app.listen(8080, address="0.0.0.0")
    print("Tornado login on :8080"); IOLoop.current().start()
PY
  ok "backend/app/main.py dibuat (login fox/bebek)"
else
  ok "backend/app/main.py ditemukan (pakai punyamu)"
fi

# ========== STREAMLIT ==========
if [ ! -f streamlit/Dockerfile ]; then
  cat > streamlit/Dockerfile <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
COPY app /app/app
RUN set -eux; \
    if [ -f /app/app/requirements.txt ]; then \
      pip install --no-cache-dir -r /app/app/requirements.txt; \
    else \
      pip install --no-cache-dir streamlit==1.37.1 pandas==2.2.2 watchdog==4.0.2; \
    fi
EXPOSE 8501
DOCKER
  ok "streamlit/Dockerfile dibuat"
fi

if [ ! -f streamlit/app/app.py ]; then
  cat > streamlit/app/app.py <<'PY'
import json, pandas as pd, streamlit as st
st.set_page_config(page_title="Monitoring", layout="wide")
st.title("🛰️ Streamlit Monitoring Dashboard")
st.write("GET /api/health -> {'ok': true}")
rows=[]; path="/var/log/suricata/eve.json"
try:
  with open(path,'r') as f:
    for ln in f.readlines()[-200:]:
      try:
        d=json.loads(ln)
        rows.append({
          "ts":d.get("timestamp"),"src":d.get("src_ip"),
          "dst":d.get("dest_ip"),
          "sig": d.get("alert",{}).get("signature") if "alert" in d else None,
          "proto":d.get("proto")})
      except: pass
except Exception as e:
  st.info(f"eve.json belum ada/akses gagal: {e}")
if rows: st.dataframe(pd.DataFrame(rows).tail(50), use_container_width=True)
st.caption("Akses via /monitor (Caddy redirect ke /login kalau belum auth).")
PY
  ok "streamlit/app/app.py dibuat (stub)"
else
  ok "streamlit/app/app.py ditemukan (pakai punyamu)"
fi

# ========== FRONTEND (Vite React) ==========
# kita cuma siapkan builder; kalau user sudah punya package.json, dipakai.
if [ ! -f frontend/Dockerfile ]; then
  cat > frontend/Dockerfile <<'DOCKER'
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
DOCKER
  ok "frontend/Dockerfile dibuat"
fi
# seed minimal kalau kosong total
if [ ! -f frontend/package.json ]; then
  cat > frontend/package.json <<'JSON'
{"name":"monitoring-frontend","private":true,"version":"0.1.0","type":"module",
"scripts":{"dev":"vite","build":"vite build","preview":"vite preview --host"},
"dependencies":{"react":"^18.3.1","react-dom":"^18.3.1"},
"devDependencies":{"vite":"^5.3.4","@vitejs/plugin-react":"^4.3.1"}}
JSON
  cat > frontend/vite.config.js <<'JS'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins:[react()], build:{outDir:'dist'}, server:{host:true,port:5173} })
JS
  cat > frontend/index.html <<'HTML'
<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Monitoring</title></head><body>
<div id="root"></div><script type="module" src="/src/main.jsx"></script>
</body></html>
HTML
  cat > frontend/src/main.jsx <<'JSX'
import React from "react"; import { createRoot } from "react-dom/client"
function App(){
  const [ok,setOk]=React.useState(null)
  React.useEffect(()=>{ fetch("/api/health").then(r=>r.json()).then(setOk).catch(()=>setOk({ok:false})) },[])
  return (<div style={{fontFamily:"sans-serif",padding:"2rem"}}>
    <h1>Monitoring Portal</h1>
    <p>API Health: <b>{ok?String(ok.ok):"loading..."}</b></p>
    <p><a href="/login">Login</a> → setelah login buka <a href="/monitor" target="_blank">/monitor</a></p>
  </div>)
}
createRoot(document.getElementById("root")).render(<App/>)
JSX
  ok "frontend skeleton dibuat (kalau kamu belum ada)"
else
  ok "frontend sudah ada (pakai punyamu)"
fi

# ========== SURICATA (build tanpa Hyperscan, host-mode, iface wlan0) ==========
if [ ! -f suricata/Dockerfile.suricata ]; then
  cat > suricata/Dockerfile.suricata <<'DOCKER'
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
 build-essential autoconf automake libtool pkg-config curl ca-certificates \
 libyaml-dev libpcap-dev libnet1-dev libjansson-dev libcap-ng-dev \
 libmagic-dev libpcre2-dev libmaxminddb-dev libnfnetlink-dev libnftnl-dev \
 libnetfilter-queue-dev rustc cargo python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG V=7.0.3
RUN curl -LO https://www.openinfosecfoundation.org/download/suricata-${V}.tar.gz \
 && tar xzf suricata-${V}.tar.gz && cd suricata-${V} \
 && CFLAGS="-O2 -pipe -march=x86-64-v2 -mtune=generic" \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
                --disable-hyperscan --disable-gccmarch-native \
 && make -j"$(nproc)" && make install-full && ldconfig \
 && cd / && rm -rf /build
RUN apt-get update && apt-get install -y --no-install-recommends ethtool jq && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/log/suricata /etc/suricata
ENTRYPOINT ["/entrypoint.sh"]
DOCKER
  ok "suricata/Dockerfile.suricata dibuat"
fi

if [ ! -f suricata/entrypoint.sh ]; then
  cat > suricata/entrypoint.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
IFACE="${SURI_IFACE:-wlan0}"
ethtool -K "$IFACE" gro off || true
ethtool -K "$IFACE" lro off || true
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update enable-source et/open abuse.ch/urlhaus || true
  for c in $(suricata-update list-categories | awk '{print $1}'); do
    case " $c " in
      *" scan "*|*" web-attack "*|*" web-php "*|*" sql "*|*" exploit "*|*" brute-force "*|*" dns "*|*" http "*|*" tls "*)
        suricata-update enable-category "$c" >/dev/null 2>&1 || true;;
      *)  suricata-update disable-category "$c" >/dev/null 2>&1 || true;;
    esac
  done
  suricata-update || true
fi
suricata -T -c /etc/suricata/suricata.yaml || { echo "[ERR] config invalid"; exit 1; }
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --runmode=autofp -D
BASH
  ok "suricata/entrypoint.sh dibuat"
fi

if [ ! -f suricata/suricata.yaml ]; then
  cat > suricata/suricata.yaml <<'YAML'
%YAML 1.1
af-packet:
  - interface: wlan0
    cluster-type: cluster_round_robin
    cluster-id: 99
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 200000
    buffer-size: 64512
outputs:
  - eve-log: { enabled: yes, filetype: regular, filename: /var/log/suricata/eve.json, community-id: yes }
  - fast-log: { enabled: yes, filename: /var/log/suricata/fast.log }
  - stats:    { enabled: yes, filename: /var/log/suricata/stats.log }
detect: { profile: medium, sgh-mpm-context: auto, prefilter: { default: mpm } }
threading: { detect-thread-ratio: 0.75 }
stream: { inline: no }
unix-command: { enabled: yes }
logging: { default-log-level: info }
YAML
  ok "suricata/suricata.yaml dibuat (iface wlan0)"
fi

# ========== docker-compose.yml ==========
backup_if_exists docker-compose.yml
cat > docker-compose.yml <<'YAML'
version: "3.9"
name: monitoring_stack

volumes:
  webroot: {}
  suri_logs:
  suri_etc:

networks:
  webnet:
    driver: bridge

services:
  frontend-builder:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    command: sh -lc "if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm run build && rm -rf /webroot/* && cp -r dist/* /webroot/ && tail -f /dev/null"
    volumes:
      - webroot:/webroot
      - ./frontend:/app
    networks: [webnet]
    restart: unless-stopped

  caddy-rev:
    image: caddy:2
    depends_on: [frontend-builder, tornado-web, streamlit-app]
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - webroot:/srv/www:ro
    networks: [webnet]
    ports: ["8080:80"]
    restart: unless-stopped

  tornado-web:
    build:
      context: ./backend
      dockerfile: Dockerfile
    env_file: [.env]
    expose: ["8080"]
    networks: [webnet]
    restart: unless-stopped

  streamlit-app:
    build:
      context: ./streamlit
      dockerfile: Dockerfile
    command: >
      streamlit run /app/app/app.py
      --server.address=0.0.0.0
      --server.port=8501
      --server.baseUrlPath=/monitor
    expose: ["8501"]
    networks: [webnet]
    volumes:
      - suri_logs:/var/log/suricata:ro
    restart: unless-stopped

  # Cloudflared token-mode; domain sudah diatur -> origin http://localhost:8080
  cloudflared:
    image: cloudflare/cloudflared:latest
    environment: [ "TUNNEL_TOKEN=${TOKEN}" ]
    network_mode: host
    command: tunnel --no-autoupdate run
    restart: unless-stopped

  # Suricata host-mode, capture iface dari .env (default wlan0)
  suricata:
    build:
      context: ./suricata
      dockerfile: Dockerfile.suricata
    network_mode: host
    cap_add: [ "NET_ADMIN", "NET_RAW" ]
    env_file: [ ".env" ]
    environment:
      - SURI_IFACE=${SURI_IFACE:-wlan0}
    volumes:
      - suri_logs:/var/log/suricata
      - suri_etc:/etc/suricata
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
    command: ["/entrypoint.sh"]
    restart: unless-stopped
YAML
ok "docker-compose.yml dibuat"

# ========== finish ==========
green "===== READY TO DEPLOY ====="
echo "1) Pastikan .env berisi TOKEN=<cloudflared_tunnel_token>"
echo "2) Build & run:   docker compose up -d --build"
echo "3) Tes lokal:     curl -sI http://localhost:8080/api/health"
echo "   Login:         http://localhost:8080/login  (fox/foxzie900 atau bebek/bebekcantik321)"
echo "   Dashboard:     http://localhost:8080/monitor"
echo "4) Enable docker on boot (sekali):  sudo systemctl enable --now docker"
echo
yellow "Catatan:"
echo "- Suricata sniff wlan0. Kalau Wi-Fi driver ngaco, pakai interface kabel (SURI_IFACE=enpXsY) atau monitor mode (mon0)."
echo "- Frontend: kita build dari folder frontend/ kamu. Kalau belum ada, skeleton minimal sudah dibuat."
#!/usr/bin/env bash
set -Eeuo pipefail

# ====== KONFIG DASAR (JALANKAN DARI FOLDER cloudflared) ======
COMPOSE="docker-compose.yml"
SVC_ST="streamlit-app"
SVC_SURI="suricata"
SVC_CADDY="caddy-rev"
SVC_FE="frontend-builder"
SVC_BACK="tornado-web"
SVC_CF="cloudflared"
DOMAIN="${1:-}"

say(){ printf ">> %s\n" "$*"; }
die(){ echo "!! $*" >&2; exit 1; }
trap 'echo "!! Gagal di baris $LINENO"; exit 2' ERR

[[ -f "$COMPOSE" ]] || die "Tidak menemukan $COMPOSE. Pastikan kamu ada di folder cloudflared/."

# ====== KODE APP STREAMLIT: LOGIN + PARSER STABIL ======
read -r -d '' APP_PY <<"PY"
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")

from typing import Dict
from _live_tail_patch import render_live

# Cred demo internal (di luar Basic Auth Caddy)
CREDENTIALS: Dict[str, str] = {
    "fox": "foxziemalam999",
    "adit": "aditidn123",
    "bebek": "bebekcantik123",
}

def require_login() -> bool:
    # sudah login?
    if st.session_state.get("logged_in") and st.session_state.get("user"):
        return True

    st.title("Masuk • Suricata Monitor")
    st.caption("Proteksi internal tambahan (melengkapi Basic Auth di proxy).")

    with st.form("login_form", clear_on_submit=False, border=True):
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        ok = st.form_submit_button("Masuk", use_container_width=True)

    if ok:
        if u in CREDENTIALS and CREDENTIALS[u] == p:
            st.session_state["logged_in"] = True
            st.session_state["user"] = u
            st.toast(f"Selamat datang, {u}!", icon="✅")
            st.rerun()
        else:
            st.error("Username/password salah.", icon="⚠️")
    return False

def logout_ui():
    with st.sidebar:
        if st.session_state.get("logged_in"):
            if st.button("Keluar", key="btn_logout_sidebar"):
                for k in ("logged_in","user"): st.session_state.pop(k, None)
                st.rerun()

def main():
    if not require_login(): return
    logout_ui()
    render_live()

if __name__ == "__main__":
    main()
PY

read -r -d '' HELPER_PY <<"PY"
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))

def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def _flatten_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["timestamp"]   = raw.get("timestamp")
    out["event_type"]  = raw.get("event_type")
    out["src_ip"]      = raw.get("src_ip")
    out["src_port"]    = raw.get("src_port")
    out["dest_ip"]     = raw.get("dest_ip")
    out["dest_port"]   = raw.get("dest_port")
    out["proto"]       = raw.get("proto")
    out["app_proto"]   = raw.get("app_proto")
    a = raw.get("alert") or {}
    out["signature"]   = a.get("signature")
    out["sig_id"]      = a.get("signature_id")
    out["severity"]    = a.get("severity")
    dns = raw.get("dns") or {}
    out["dns_query"]   = dns.get("rrname") or dns.get("query")
    out["dns_rrtype"]  = dns.get("rrtype")
    out["dns_rcode"]   = dns.get("rcode")
    http = raw.get("http") or {}
    out["http_host"]   = http.get("hostname")
    out["http_url"]    = http.get("url")
    out["http_status"] = http.get("status")
    flow = raw.get("flow") or {}
    out["flow_to_srv"] = flow.get("bytes_toserver")
    out["flow_to_cli"] = flow.get("bytes_toclient")
    return out

def parse_eve_lines(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln: continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame, event_type, sig_sub, src_sub, dst_sub, last_minutes):
    out = df.copy()
    if event_type and event_type != "ALL":
        out = out[out["event_type"] == event_type]
    if sig_sub:
        out = out[out["signature"].fillna("").str.contains(sig_sub, case=False, na=False)]
    if src_sub:
        out = out[out["src_ip"].fillna("").str.contains(src_sub, case=False, na=False)]
    if dst_sub:
        out = out[out["dest_ip"].fillna("").str.contains(dst_sub, case=False, na=False)]
    if last_minutes and "timestamp" in out.columns and pd.api.types.is_datetime64_any_dtype(out["timestamp"]):
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(last_minutes))
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    with st.sidebar:
        st.header("Filter")
        et  = st.selectbox("Event Type", ["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    # Tombol refresh TUNGGAL dengan key unik → cegah DuplicateWidgetID
    if st.button("Refresh sekarang", key="btn_refresh_top_unique"):
        st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)
    dff = df_filter(df, et, sig, src, dst, win if win and int(win) > 0 else None)

    c1,c2,c3,c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    if not dff.empty:
        a,b = st.columns(2)
        with a:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with b:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    csv_io = io.StringIO(); dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(),
                       file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(),
                       file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    st.subheader("Tail (last 20 raw lines)")
    st.code("\n".join(lines[-20:]), language="json")

    if auto:
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY

# ====== FUNGSI UTIL ======
cid(){ docker compose -f "$COMPOSE" ps -q "$1" 2>/dev/null || true; }
up(){ docker compose -f "$COMPOSE" up -d "$@" >/dev/null; }

ensure_up(){
  say "Pastikan stack hidup (utama)..."
  up "$SVC_CADDY" "$SVC_ST" "$SVC_SURI" "$SVC_FE" "$SVC_BACK" "$SVC_CF"
}

fix_caddy(){
  say "Cek & patch Caddyfile (public / & /healthz, proteksi /monitor)..."
  local HF="caddy/Caddyfile"
  [[ -f "$HF" ]] || die "Tidak menemukan $HF"
  # Public /healthz dan /
  if ! grep -qE 'handle_path +/healthz' "$HF"; then
    sed -ri 's@(:80 *\{)@\1\n  handle_path /healthz { respond "ok" 200 }\n@' "$HF"
  fi
  # Blok monitor (tanpa strip_prefix)
  if ! grep -qE 'handle_path +/monitor\*' "$HF"; then
    sed -ri 's@(:80 *\{)@\1\n  handle_path /monitor* {\n    import auth\n    reverse_proxy streamlit-app:8501\n  }\n@' "$HF"
  else
    # pastikan tidak ada strip_prefix di blok /monitor
    sed -ri '/handle_path +\/monitor\*/,/}/ s/strip_path_prefix.*//' "$HF"
  fi
  # ganti basicauth -> basic_auth (naming baru)
  sed -ri 's/\bbasicauth\b/basic_auth/g' "$HF"

  # Reload (fallback: restart container bila RO)
  if ! docker compose -f "$COMPOSE" exec -T "$SVC_CADDY" caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null 2>&1; then
    say "Fmt gagal (RO)."
  fi
  if ! docker compose -f "$COMPOSE" exec -T "$SVC_CADDY" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    say "Reload gagal → restart Caddy."
    docker compose -f "$COMPOSE" restart "$SVC_CADDY" >/dev/null
  fi
}

build_frontend(){
  say "Build & publish frontend (Vite) → /webroot"
  up "$SVC_FE"
  docker compose -f "$COMPOSE" exec -T "$SVC_FE" sh -lc '
    (test -f package.json && jq -e . >/dev/null 2>&1) || true
    npm i --silent --no-fund --no-audit >/dev/null 2>&1 || npm i
    npm run build || exit 1
    rm -rf /webroot/* && cp -r dist/* /webroot/
    # Patch: matikan Rocket Loader & force type=module
    find /webroot -type f -name "*.html" -maxdepth 1 -print0 | xargs -0 -I{} sh -lc "
      sed -ri '\''s@<script @<script data-cfasync=\"false\" @g'\'' {};
      sed -ri '\''s@type=\"[^\"]*-module\"@type=\"module\"@g'\'' {}
    "'
}

seed_suricata(){
  say "Periksa Suricata & seed eve.json bila kosong..."
  up "$SVC_SURI"
  docker compose -f "$COMPOSE" exec -T "$SVC_SURI" sh -lc '
    p=/var/log/suricata/eve.json
    mkdir -p /var/log/suricata
    if [ ! -s "$p" ]; then
      TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
      : > "$p"
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.10\",\"dest_ip\":\"10.0.0.5\",\"alert\":{\"signature\":\"DEMO Seed 1\",\"severity\":2}}" >> "$p"
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"dns\",\"src_ip\":\"192.168.1.11\",\"dest_ip\":\"1.1.1.1\",\"dns\":{\"query\":\"example.com\",\"rrtype\":\"A\",\"rcode\":\"NOERROR\"}}" >> "$p"
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"flow\",\"src_ip\":\"192.168.1.12\",\"dest_ip\":\"10.0.0.8\",\"flow\":{\"bytes_toserver\":1234,\"bytes_toclient\":4321}}" >> "$p"
      chmod 666 "$p"
    fi
  ' || true
}

check_shared_volume(){
  say "Cek volume /var/log/suricata terpampang di Streamlit & Suricata..."
  local a b
  a=$(docker inspect "$(cid "$SVC_SURI")"    --format '{{range .Mounts}}{{if eq .Destination "/var/log/suricata"}}{{.Name}}{{end}}{{end}}' || true)
  b=$(docker inspect "$(cid "$SVC_ST")"      --format '{{range .Mounts}}{{if eq .Destination "/var/log/suricata"}}{{.Name}}{{end}}{{end}}' || true)
  echo "   Suricata mounts : ${a:-<none>}"
  echo "   Streamlit mounts: ${b:-<none>}"
  if [[ -n "$a" && -n "$b" && "$a" == "$b" ]]; then
    echo "   OK: share volume sama."
  else
    echo "   WARN: volume berbeda/none → pastikan docker-compose map volume yang sama untuk kedua container."
  fi
}

deploy_streamlit(){
  say "Deploy ulang kode Streamlit (login + parser stabil)..."
  up "$SVC_ST"
  docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'rm -rf /app/app && mkdir -p /app/app'
  printf "%s" "$APP_PY"    | docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'cat > /app/app/app.py'
  printf "%s" "$HELPER_PY" | docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'cat > /app/app/_live_tail_patch.py'
  docker compose -f "$COMPOSE" restart "$SVC_ST" >/dev/null
}

self_test_origin(){
  say "Self-test origin (Caddy 127.0.0.1:8080)"
  echo -n "  /healthz : "; curl -sI http://127.0.0.1:8080/healthz | head -n1 || true
  echo -n "  /        : "; curl -sI http://127.0.0.1:8080/        | head -n1 || true
  echo -n "  /monitor : "; curl -sI http://127.0.0.1:8080/monitor | head -n1 || true
}

self_test_cf(){
  [[ -z "$DOMAIN" ]] && return 0
  say "Tes via Cloudflare: https://$DOMAIN"
  echo -n "  /healthz : "; curl -sI "https://$DOMAIN/healthz" | head -n1 || true
  echo -n "  /monitor : "; curl -sI "https://$DOMAIN/monitor" | head -n1 || true
}

streamlit_smoketest(){
  say "Smoketest Streamlit (tail 80 log):"
  docker compose -f "$COMPOSE" logs -n 80 "$SVC_ST" || true
  say "Cari error umum:"
  docker compose -f "$COMPOSE" logs -n 400 "$SVC_ST" | egrep -n "DuplicateWidgetID|set_page_config|experimental_rerun|ModuleNotFoundError|Traceback" || true
}

# ====== RUN ======
ensure_up
fix_caddy
build_frontend
seed_suricata
check_shared_volume
deploy_streamlit
self_test_origin
self_test_cf
streamlit_smoketest

say "DONE ✓ — akses /monitor:"
echo "   1) Basic Auth (Caddy) → lalu"
echo "   2) Login internal Streamlit:"
echo "      - fox   / foxziemalam999"
echo "      - adit  / aditidn123"
echo "      - bebek / bebekcantik123"
#!/usr/bin/env bash
# doctor_fix_streamlit_frontend.sh
set -euo pipefail

BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"

SVC_S="streamlit-app"
SVC_F="frontend-builder"
APP_CONT="/app/app/app.py"
APP_HOST="$BASE/streamlit/app/app.py"     # kalau ada versi host (bind)

echo ">> Compose: $COMPOSE"
[ -f "$COMPOSE" ] || { echo "ERR: compose file tidak ketemu"; exit 1; }

echo ">> Pastikan stack jalan..."
docker compose -f "$COMPOSE" up -d

CID_S="$(docker compose -f "$COMPOSE" ps -q $SVC_S)"
CID_F="$(docker compose -f "$COMPOSE" ps -q $SVC_F)"
[ -n "$CID_S" ] || { echo "ERR: container $SVC_S belum jalan"; exit 1; }
[ -n "$CID_F" ] || { echo "ERR: container $SVC_F belum jalan"; exit 1; }

###############################################################################
# STREAMLIT: hapus 'experimental_rerun' + patch live log + info kredensial
###############################################################################
echo ">> Patch Streamlit: buang experimental_rerun + tambah live log panel..."

# 1) Backup di dalam container
docker compose -f "$COMPOSE" exec -T $SVC_S sh -lc "cp -a $APP_CONT ${APP_CONT}.bak.$(date +%Y%m%d_%H%M%S) || true"

# 2) Benerin pemakaian rerun:
#    - hapus baris yg hanya mereferensikan 'st.experimental_rerun'
#    - ganti 'st.experimental_rerun(' --> 'st.rerun('
docker compose -f "$COMPOSE" exec -T $SVC_S sh -lc "
  if grep -q 'st.experimental_rerun[[:space:]]*$' $APP_CONT; then
    sed -ri '/st\.experimental_rerun[[:space:]]*$/d' $APP_CONT
  fi
  sed -ri \"s/st\\.experimental_rerun\\(/st.rerun(/g\" $APP_CONT
"

# 3) Sisipkan helper panel Live Log (idempotent)
docker compose -f "$COMPOSE" exec -T $SVC_S sh -lc '
  LIVE="/app/app/_live_tail_patch.py"
  if [ ! -f "$LIVE" ]; then
    cat > "$LIVE" <<PY
import os, time, json, pathlib
import streamlit as st
from collections import deque

EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")

def read_last_lines(path, n=200):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    dq = deque(maxlen=n)
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                dq.append(s)
    return list(dq)

def render_live():
    st.header("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari ID-NETWORKERS")

    with st.expander("Kredensial Akses (Basic Auth via Caddy)"):
        st.write("**Username:** `fox`, `adit`, `bebek`")
        st.write("**Password:** `foxziemalam999`, `aditidn123`, `bebekcantik123`")
        st.warning("⚠️ Jangan tampilkan ini di produksi.")

    colA, colB = st.columns([2,1])
    with colB:
        auto = st.toggle("Live refresh", value=True)
        every = st.number_input("Refresh (detik)", 1, 30, 2)
        limit = st.slider("Baris terakhir", 50, 2000, 300, 50)
    with colA:
        st.markdown(f"**File:** `{EVE_PATH}`")

    holder = st.empty()

    # tampilan awal
    raw_lines = read_last_lines(EVE_PATH, limit)
    rows = []
    for s in raw_lines:
        try:
            rows.append(json.loads(s))
        except Exception:
            rows.append({"_raw": s})
    holder.dataframe(rows, use_container_width=True, hide_index=True)

    if auto:
        time.sleep(every)
        st.rerun()

def inject():
    # sisipkan tombol navigasi sederhana di sidebar jika ingin
    pass
PY
  fi
'

# 4) Pastikan app.py mengimport & memanggil render_live() (sekali saja)
docker compose -f "$COMPOSE" exec -T $SVC_S sh -lc "
  if ! grep -q \"from app._live_tail_patch import render_live\" $APP_CONT; then
    awk '
      NR==1 { print \"from app._live_tail_patch import render_live\" }
      { print }
      END { print \"\\nif __name__ == \\\"__main__\\\":\\n    render_live()\" }
    ' $APP_CONT > ${APP_CONT}.new && mv ${APP_CONT}.new $APP_CONT
  fi
"

# 5) Restart Streamlit
docker compose -f "$COMPOSE" restart $SVC_S >/dev/null

###############################################################################
# FRONTEND (Vite): install deps kalau belum, build, publish ke /webroot
###############################################################################
echo ">> Perbaiki frontend: install deps & build..."

# install dep bila belum ada
docker compose -f "$COMPOSE" exec -T $SVC_F sh -lc '
  set -e
  cd /app
  # Jika framer-motion belum ada, install (sekalian lucide-react)
  if ! node -e "require.resolve(\"framer-motion\")" >/dev/null 2>&1; then
    echo ">> npm install framer-motion lucide-react ..."
    npm install framer-motion@latest lucide-react@latest
  fi
  # pastikan node_modules konsisten lalu build
  if [ -f package-lock.json ]; then
    npm ci || npm install
  else
    npm install
  fi
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
'

###############################################################################
# RELOAD CADDY (opsional; hanya load ulang, tidak rewrite file)
###############################################################################
echo ">> Reload Caddy..."
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile || true

###############################################################################
# TES CEPAT
###############################################################################
echo ">> Tes origin:"
curl -sI http://127.0.0.1:8080/healthz | head -n1 || true
curl -sI http://127.0.0.1:8080/        | head -n1 || true
curl -sI http://127.0.0.1:8080/monitor | head -n1 || true
echo ">> Done."
#!/usr/bin/env bash
set -Eeuo pipefail

# --- Konfigurasi kredensial DEMO (sinkron Caddy & landing) ---
CREDS=("fox:foxziemalam999" "adit:aditidn123" "bebek:bebekcantik123")

# --- Autodetect compose file (root atau subfolder) ---
if [[ -f "cloudflared/docker-compose.yml" ]]; then
  COMPOSE="cloudflared/docker-compose.yml"
elif [[ -f "./docker-compose.yml" ]]; then
  COMPOSE="./docker-compose.yml"
else
  echo "!! Tidak menemukan docker-compose.yml" >&2
  exit 1
fi

SVC_STREAMLIT="streamlit-app"
SVC_CADDY="caddy-rev"
SVC_FE="frontend-builder"
CADDY_HOST_DIR="cloudflared/caddy"
CADDYFILE="$CADDY_HOST_DIR/Caddyfile"

say(){ printf ">> %s\n" "$*"; }

# -----------------------------
# 0) Pastikan stack hidup
# -----------------------------
say "Up stack..."
docker compose -f "$COMPOSE" up -d >/dev/null

CID_STREAMLIT="$(docker compose -f "$COMPOSE" ps -q "$SVC_STREAMLIT" || true)"
CID_CADDY="$(docker compose -f "$COMPOSE" ps -q "$SVC_CADDY" || true)"
CID_FE="$(docker compose -f "$COMPOSE" ps -q "$SVC_FE" || true)"
[[ -n "$CID_STREAMLIT" ]] || { echo "!! Container $SVC_STREAMLIT tidak ditemukan"; exit 2; }
[[ -n "$CID_CADDY" ]] || { echo "!! Container $SVC_CADDY tidak ditemukan"; exit 2; }
[[ -n "$CID_FE" ]] || { echo "!! Container $SVC_FE tidak ditemukan"; exit 2; }

# -----------------------------
# 1) Sinkron BASIC AUTH Caddy
# -----------------------------
say "Generate bcrypt hash (via caddy:2) & patch Caddyfile..."
mkdir -p "$CADDY_HOST_DIR"
AUTH_TMP="$(mktemp)"
{
  echo "(auth) {"
  echo "  basic_auth {"
  for kv in "${CREDS[@]}"; do
    usr="${kv%%:*}"
    pass="${kv#*:}"
    hash="$(docker run --rm caddy:2 caddy hash-password --algorithm bcrypt --plaintext "$pass")"
    printf "    %-6s %s\n" "$usr" "$hash"
  done
  echo "  }"
  echo "}"
} > "$CADDY_HOST_DIR/.auth.hashes"

# Tulis Caddyfile minimal yang valid & public landing, protect /monitor
cat > "$CADDYFILE" <<'CFG'
{
  auto_https off
  servers :80 {
    protocols h1 h2c
  }
}

(auth) {
  # Placeholder; akan digantikan sed -e '/(auth)/,/}/' di bawah
}

:80 {
  handle_path /healthz { respond "ok" 200 }

  # Streamlit Wajib Basic Auth; prefix /monitor dipertahankan
  handle /monitor* {
    import auth
    reverse_proxy streamlit-app:8501
  }

  # API contoh (jika ada backend), juga protect
  handle /api/* {
    import auth
    reverse_proxy tornado-web:8080
  }

  # Landing React (public)
  handle {
    root * /srv/www
    encode zstd gzip
    try_files {path} /index.html
    file_server
  }
}
CFG

# Sisipkan blok auth hasil hash
awk '
  BEGIN { repl=0 }
  /^\(auth\)/ { print; repl=1; next }
  repl==1 {
    # skip sampai ketemu }
    if ($0 ~ /^\}/) { repl=2; next }
    next
  }
  { print }
' "$CADDYFILE" > "$CADDYFILE.tmp"

# temp merge auth hashes ke Caddyfile.tmp
awk '1' "$CADDYFILE.tmp" > "$CADDYFILE"
sed -i '/^(auth)/,/^}/d' "$CADDYFILE"
# temp header + auth + footer
{
  # header sebelum (auth)
  awk 'BEGIN{p=1} /^\(auth\)/{p=0} p{print}' "$CADDYFILE.tmp"
  # auth baru
  cat "$CADDY_HOST_DIR/.auth.hashes"
  # footer setelah blok auth lama
  awk 'BEGIN{p=0} /^\(auth\)/{p=1;next} p{print}' "$CADDYFILE.tmp"
} > "$CADDYFILE.new" && mv "$CADDYFILE.new" "$CADDYFILE" && rm -f "$CADDYFILE.tmp"

# Format pakai image caddy (hindari RO filesystem)
docker run --rm -v "$PWD/$CADDY_HOST_DIR:/etc/caddy" caddy:2 caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null 2>&1 || true

say "Reload Caddy (fallback restart bila gagal)..."
if ! docker compose -f "$COMPOSE" exec -T "$SVC_CADDY" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  docker compose -f "$COMPOSE" restart "$SVC_CADDY" >/dev/null
fi

# -----------------------------
# 2) Redeploy STREAMLIT (parser & UI)
# -----------------------------
say "Deploy app.py & helper ke container (pakai docker exec tanpa -T)..."
docker exec "$CID_STREAMLIT" sh -lc 'mkdir -p /app/app'

# app.py – hanya 1x set_page_config dan import helper lokal
docker exec "$CID_STREAMLIT" sh -lc 'cat > /app/app/app.py <<'\''PY'\''
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")
from _live_tail_patch import render_live
render_live()
PY'

# helper – live tail + filter + export CSV/JSONL + auto refresh (key unik)
docker exec "$CID_STREAMLIT" sh -lc 'cat > /app/app/_live_tail_patch.py <<'\''PY'\''
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))

def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def _flatten_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["timestamp"]   = raw.get("timestamp")
    out["event_type"]  = raw.get("event_type")
    out["src_ip"]      = raw.get("src_ip")
    out["src_port"]    = raw.get("src_port")
    out["dest_ip"]     = raw.get("dest_ip")
    out["dest_port"]   = raw.get("dest_port")
    out["proto"]       = raw.get("proto")
    out["app_proto"]   = raw.get("app_proto")
    a = raw.get("alert") or {}
    out["signature"]   = a.get("signature")
    out["sig_id"]      = a.get("signature_id")
    out["severity"]    = a.get("severity")
    dns = raw.get("dns") or {}
    out["dns_query"]   = dns.get("rrname") or dns.get("query")
    out["dns_rrtype"]  = dns.get("rrtype")
    out["dns_rcode"]   = dns.get("rcode")
    http = raw.get("http") or {}
    out["http_host"]   = http.get("hostname")
    out["http_url"]    = http.get("url")
    out["http_status"] = http.get("status")
    flow = raw.get("flow") or {}
    out["flow_to_srv"] = flow.get("bytes_toserver")
    out["flow_to_cli"] = flow.get("bytes_toclient")
    return out

def parse_eve_lines(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln: continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame, event_type, sig_sub, src_sub, dst_sub, last_minutes):
    out = df.copy()
    if event_type and event_type != "ALL":
        out = out[out["event_type"] == event_type]
    if sig_sub:
        out = out[out["signature"].fillna("").str.contains(sig_sub, case=False, na=False)]
    if src_sub:
        out = out[out["src_ip"].fillna("").str.contains(src_sub, case=False, na=False)]
    if dst_sub:
        out = out[out["dest_ip"].fillna("").str.contains(dst_sub, case=False, na=False)]
    if last_minutes and "timestamp" in out.columns and pd.api.types.is_datetime64_any_dtype(out["timestamp"]):
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(last_minutes))
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    with st.sidebar:
        st.header("Filter")
        et  = st.selectbox("Event Type", ["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    if st.button("Refresh sekarang", key="btn_refresh_top"):
        st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)
    dff = df_filter(df, et, sig, src, dst, win if win and int(win) > 0 else None)

    c1,c2,c3,c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    if not dff.empty:
        a,b = st.columns(2)
        with a:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with b:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    csv_io = io.StringIO(); dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(),
                       file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(),
                       file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    st.subheader("Tail (last 20 raw lines)")
    preview = "\n".join(lines[-20:])
    st.code(preview, language="json")

    if auto:
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY'

say "Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC_STREAMLIT" >/dev/null

# -----------------------------
# 3) Build & publish FRONTEND
# -----------------------------
say "Build & publish frontend Vite..."
docker compose -f "$COMPOSE" exec -T "$SVC_FE" sh -lc '
set -e
if [ -f package-lock.json ] || [ -d node_modules ]; then npm i >/dev/null 2>&1 || npm i; fi
npm run build
rm -rf /webroot/* && cp -r dist/* /webroot/
' >/dev/null

# -----------------------------
# 4) Self tests
# -----------------------------
say "Self-test origin (Caddy 127.0.0.1:8080)..."
echo -n "  /healthz : "; curl -sI http://127.0.0.1:8080/healthz | sed -n '1p'
echo -n "  /        : "; curl -sI http://127.0.0.1:8080/        | sed -n '1p'
echo -n "  /monitor : "; curl -sI http://127.0.0.1:8080/monitor | sed -n '1p'

say "Tail log streamlit (40 baris):"
docker compose -f "$COMPOSE" logs -n 40 "$SVC_STREAMLIT" || true

say "Selesai ✔"
#!/usr/bin/env bash
set -euo pipefail
COMPOSE="${COMPOSE:-$(pwd)/docker-compose.yml}"

echo ">> Ensure App.jsx has default export..."
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc '
  set -e
  cd /app

  test -f src/App.jsx || { echo "ERR: src/App.jsx tidak ada"; exit 1; }

  # Jika App.jsx tidak memiliki default export, tambahkan.
  if ! grep -Eq "export default( function)? App" src/App.jsx; then
    # Cek apakah ada deklarasi fungsi bernama App
    if grep -Eq "^\\s*function\\s+App\\s*\\(" src/App.jsx; then
      echo ">> Tambah baris export default App;"
      printf "\nexport default App;\n" >> src/App.jsx
    else
      echo ">> Bungkus jadi komponen default minimal"
      cat > src/App.jsx <<'JS'
import React from "react";

function App() {
  return (
    <div style={{padding: 24}}>
      <h1>Suricata Monitor</h1>
      <p>Landing React berhasil dimuat.</p>
      <a href="/monitor">Ke Dashboard Streamlit</a>
    </div>
  );
}
export default App;
JS
    fi
  fi

  echo ">> Normalize main.jsx (default import + import CSS + render)..."
  cat > src/main.jsx <<'JS'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import './index.css'

createRoot(document.getElementById('root')).render(<App />)
JS

  echo ">> Build & publish..."
  (npm ci || npm install)
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
'
echo ">> Done. Coba refresh landing."
#!/usr/bin/env bash
set -euo pipefail

COMPOSE="${COMPOSE:-$(pwd)/docker-compose.yml}"

echo ">> Perbaiki main.jsx (quotes) & rebuild frontend..."
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc '
  set -e
  cd /app/src

  # Tulis ulang main.jsx pakai printf (aman dari quoting aneh)
  printf "%s\n" \
"import React from \"react\"" \
"import { createRoot } from \"react-dom/client\"" \
"import App from \"./App.jsx\"" \
"import \"./index.css\"" \
"" \
"createRoot(document.getElementById(\"root\")).render(<App />)" > main.jsx

  echo "----- main.jsx (preview) -----"
  sed -n "1,20p" main.jsx
  echo "------------------------------"

  # Pastikan App.jsx punya default export
  if ! grep -Eq "export default( function)? App" App.jsx; then
    if grep -Eq "^[[:space:]]*function[[:space:]]+App[[:space:]]*\\(" App.jsx; then
      printf "\nexport default App;\n" >> App.jsx
    else
      # fallback minimal kalau file kosong/aneh
      cat > App.jsx <<'JS'
import React from "react";
function App() {
  return (
    <div style={{padding: 24}}>
      <h1>Suricata Monitor</h1>
      <p>Landing React berhasil dimuat.</p>
      <a href="/monitor">Ke Dashboard Streamlit</a>
    </div>
  );
}
export default App;
JS
    fi
  fi

  cd /app
  (npm ci || npm install)
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
'

echo ">> Perbaiki Streamlit (import & rerun)..."
docker compose -f "$COMPOSE" exec -T streamlit-app sh -lc '
  set -e
  cd /app/app

  # experimental_rerun -> rerun()
  if grep -q "experimental_rerun" app.py; then
    sed -ri "s/\\bst\\.experimental_rerun\\b/st.rerun()/g" app.py
  fi

  # from app._live_tail_patch -> from _live_tail_patch
  if grep -q "from app\\._live_tail_patch" app.py; then
    sed -ri "s/from app\\._live_tail_patch/from _live_tail_patch/g" app.py
  fi

  # Pastikan modul helper ada
  if [ ! -f _live_tail_patch.py ]; then
    cat > _live_tail_patch.py <<'PY'
import os, time, itertools
import streamlit as st

def render_live(path="/var/log/suricata/eve.json", limit=200, interval=1.5):
    st.subheader("Live tail eve.json")
    if not os.path.exists(path):
        st.info(f"{path} tidak ditemukan")
        return
    # snapshot sederhana (refresh manual)
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()[-int(limit):]
        st.code("".join(lines)[-8000:], language="json")
        if st.button("Refresh"):
            st.rerun()
    except Exception as e:
        st.warning(f"Tail error: {e}")
PY
  fi
'

docker compose -f "$COMPOSE" restart streamlit-app >/dev/null

echo ">> Selesai. Cek cepat:"
echo "  curl -I http://127.0.0.1:8080/                # 200 (landing)"
echo "  curl -I http://127.0.0.1:8080/healthz         # 200"
echo "  curl -I http://127.0.0.1:8080/monitor         # 401"
echo "  curl -I -u fox:foxziemalam999 http://127.0.0.1:8080/monitor  # 200"
#!/usr/bin/env bash
set -euo pipefail

# --- Locate compose file ---
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${BASE_DIR}/docker-compose.yml" ]]; then
  COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
elif [[ -f "${BASE_DIR}/cloudflared/docker-compose.yml" ]]; then
  COMPOSE_FILE="${BASE_DIR}/cloudflared/docker-compose.yml"
else
  echo "ERR: docker-compose.yml tidak ditemukan di ${BASE_DIR} atau ${BASE_DIR}/cloudflared"
  exit 1
fi
COMPOSE="docker compose -f ${COMPOSE_FILE}"

# --- Project & volume name ---
PROJECT="$($COMPOSE config 2>/dev/null | awk '/^name:/{print $2; exit}' || true)"
PROJECT="${PROJECT:-monitoring_stack}"
VOL_WEBROOT="${PROJECT}_webroot"
VOL_SURI_LOGS="${PROJECT}_suri_logs"

echo ">> Compose file: ${COMPOSE_FILE}"
echo ">> Project: ${PROJECT}"
echo ">> Volumes: ${VOL_WEBROOT}, ${VOL_SURI_LOGS}"

echo ">> Pastikan stack jalan..."
$COMPOSE up -d --build

# --- Patch file HTML agar Rocket Loader tidak ganggu ---
echo ">> Patch bundle HTML agar bypass Rocket Loader..."
docker run --rm -v "${VOL_WEBROOT}:/webroot" busybox sh -euxc '
  # Cari semua *.html lalu patch:
  find /webroot -type f -name "*.html" 2>/dev/null | while IFS= read -r f; do
    # Tambah data-cfasync="false" supaya Rocket Loader nggak utak-atik script tag
    sed -ri "s@<script @<script data-cfasync=\"false\" @g" "$f"
    # Ubah type yang di-hash oleh Rocket Loader kembali ke module
    sed -ri "s@type=\"[^\"]*-module\"@type=\"module\"@g" "$f"
  done
'

# --- Landing SPA + healthz ---
echo ">> Simpan index lama (jika ada) & buat landing SPA..."
docker run --rm -v "${VOL_WEBROOT}:/webroot" busybox sh -lc '
  if [ -f /webroot/index.html ] && [ ! -f /webroot/index.react.html ]; then
    mv /webroot/index.html /webroot/index.react.html
  fi
  cat > /webroot/index.html <<EOF
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Monitoring</title>
  <style>
    html,body{margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;background:#0b1220;color:#e7eef7}
    .wrap{max-width:880px;margin:6vh auto;padding:24px}
    .card{background:#111a2e;border:1px solid #203055;border-radius:18px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    h1{margin:0 0 12px;font-size:28px} p.lead{opacity:.9;margin:0 0 16px}
    .grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:16px}
    a.btn{display:block;text-decoration:none;text-align:center;padding:12px 16px;border-radius:12px;border:1px solid #2b3f6a;background:#1a2a4a;color:#e7eef7;transition:all .15s}
    a.btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,0,0,.25)}
    small{opacity:.7}.ok{color:#8ef59f}.bad{color:#ff9a9a} code{background:#0c1426;border:1px solid #1e2d52;border-radius:8px;padding:2px 6px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Monitoring Suricata</h1>
      <p class="lead"><strong>Untuk menyelesaikan tugas akhir dari ID-NETWORKERS</strong></p>
      <p>Data Suricata dipresentasikan dengan <em>Streamlit</em> di <code>/monitor</code>. Anda juga bisa mengunduh <code>eve.json</code> atau <code>eve.csv</code>.</p>
      <div id="health"></div>
      <div class="grid">
        <a class="btn" href="/monitor">Buka Monitor (Streamlit)</a>
        <a class="btn" href="/eve.json" download>Unduh EVE (JSON)</a>
        <a class="btn" href="/eve.csv" download>Unduh EVE (CSV)</a>
        <a class="btn" href="/index.react.html">Versi React (jika ada)</a>
      </div>
      <p style="margin-top:16px"><small>Jika halaman putih/blank, itu biasanya dari Rocket Loader—sudah di-bypass otomatis.</small></p>
    </div>
  </div>
  <script data-cfasync="false">
    fetch("/healthz",{cache:"no-store"})
      .then(r=>document.getElementById("health").innerHTML=r.ok?"<p class=ok>Health: OK</p>":"<p class=bad>Health: gagal</p>")
      .catch(()=>document.getElementById("health").innerHTML="<p class=bad>Health: gagal</p>");
  </script>
</body>
</html>
EOF
  # sediakan /healthz (200 OK)
  printf "ok" >/webroot/healthz
'

# --- Salin eve.json dan buat eve.csv ---
echo ">> Ekspor eve.json -> webroot dan buat eve.csv..."
docker run --rm -v "${VOL_SURI_LOGS}:/logs:ro" -v "${VOL_WEBROOT}:/webroot" busybox sh -lc '
  [ -f /logs/eve.json ] && cp -af /logs/eve.json /webroot/eve.json || true
'
docker run --rm -v "${VOL_SURI_LOGS}:/logs:ro" -v "${VOL_WEBROOT}:/webroot" python:3.11-alpine sh -lc '
python - <<PY
import json, csv, os, sys
src="/logs/eve.json"; dst="/webroot/eve.csv"
if not os.path.exists(src): sys.exit(0)
fields=["timestamp","event_type","src_ip","src_port","dest_ip","dest_port","proto","signature","category","severity"]
with open(dst,"w",newline="",encoding="utf-8") as fcsv:
    w=csv.writer(fcsv); w.writerow(fields)
    with open(src,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: o=json.loads(line)
            except: continue
            alert = o.get("alert") or {}
            row=[o.get("timestamp",""),o.get("event_type",""),o.get("src_ip",""),o.get("src_port",""),
                 o.get("dest_ip",""),o.get("dest_port",""),o.get("proto",""),
                 alert.get("signature",""),alert.get("category",""),alert.get("severity","")]
            w.writerow(row)
print("Wrote",dst)
PY
'

# --- Reload Caddy (kalau ada perubahan di file) ---
echo ">> Reload Caddy..."
$COMPOSE exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile || true

echo "OK. Tes cepat:"
echo "  curl -I http://127.0.0.1:8080/healthz         # 200 OK"
echo "  curl -I -u fox:foxziemalam999 http://127.0.0.1:8080/"
echo "  buka http://127.0.0.1:8080/  (auth basic)"
echo "  unduh http://127.0.0.1:8080/eve.json & /eve.csv"
#!/usr/bin/env bash
set -Eeuo pipefail

# ===== CONFIG (bisa di-override via env) =====
FRONTEND_DIR="${FRONTEND_DIR:-./frontend}"
WEBROOT="${WEBROOT:-/var/www/html}"
STREAMLIT_APP_DIR="${STREAMLIT_APP_DIR:-/home/eve/monitoring}"   # folder app Streamlit
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
COMPOSE_FILE="${COMPOSE_FILE:-./docker-compose.yaml}"
STREAMLIT_INTERNAL_URL="${STREAMLIT_INTERNAL_URL:-http://streamlit:8501}"

BASIC_AUTH_USER="${BASIC_AUTH_USER:-fox}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-foxziemalam999}"

say() { printf "\033[1;32m>>\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m!!\033[0m %s\n" "$*"; }
die(){ printf "\033[1;31mXX\033[0m %s\n" "$*"; exit 1; }

# ===== PRECHECK =====
command -v node >/dev/null || die "Node tidak ditemukan. Install Node 18+."
NODE_MAJ="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJ" -ge 18 ] || die "Butuh Node >= 18 (Vite 5). Node sekarang: $(node -v)"

# ===== 1) PATCH STREAMLIT =====
say "Patch Streamlit app..."
if grep -Rqs "experimental_rerun" "$STREAMLIT_APP_DIR"; then
  sudo sed -ri 's/\bst\.experimental_rerun\b/st.rerun/g' $(grep -Rl "experimental_rerun" "$STREAMLIT_APP_DIR")
  say "  - Replace st.experimental_rerun -> st.rerun"
else
  say "  - Tidak ada experimental_rerun (OK)"
fi

# helper opsional untuk X-Remote-User (via query ?user=)
PATCH_FILE="$STREAMLIT_APP_DIR/_remote_user_patch.py"
if [ ! -f "$PATCH_FILE" ]; then
  sudo tee "$PATCH_FILE" >/dev/null <<'PY'
import os, streamlit as st
hdr = os.getenv("STREAMLIT_REMOTE_USER_HEADER", "X-Remote-User")
# Catatan: Streamlit tidak expose header langsung.
# Fallback: ?user= di URL -> st.session_state["_remote_user"]
qs = st.query_params
user = qs.get("user", [None])[0] if hasattr(qs, "get") else None
if user:
    st.session_state["_remote_user"] = user
PY
  say "  - Tambah helper _remote_user_patch.py"
fi

# ===== 2) CADDY ROUTE /monitor + Basic Auth + header X-Remote-User =====
say "Terapkan header X-Remote-User & route /monitor di Caddy..."
if [ -f "$CADDYFILE" ]; then
  sudo cp -a "$CADDYFILE" "${CADDYFILE}.bak.$(date +%s)"
  if ! grep -qE 'path[[:space:]]+/monitor\*' "$CADDYFILE"; then
    # sisipkan blok route @monitor di akhir server block
    sudo bash -c "cat >> '$CADDYFILE'" <<CFG

@monitor path /monitor*
route @monitor {
    basicauth /* {
        ${BASIC_AUTH_USER} ${BASIC_AUTH_PASS}
        adit aditidn123
        bebek bebekcantik123
    }
    header_up X-Remote-User {http.auth.user.id}
    handle_path /monitor* {
        reverse_proxy ${STREAMLIT_INTERNAL_URL}
    }
}
CFG
    say "  - Tambah blok /monitor + Basic Auth"
  else
    say "  - /monitor sudah ada (skip)"
  fi
  sudo caddy reload 2>/dev/null || sudo systemctl reload caddy || warn "Reload Caddy gagal (cek manual)."
else
  warn "Caddyfile tidak ditemukan di $CADDYFILE (skip bagian ini)."
fi

# ===== 3) FRONTEND: install deps (framer-motion/lucide) kalau dipakai, build, publish =====
say "Build & publish frontend..."
[ -d "$FRONTEND_DIR" ] || die "FRONTEND_DIR tidak ada: $FRONTEND_DIR"
pushd "$FRONTEND_DIR" >/dev/null

PKG= npm
command -v pnpm >/dev/null && PKG=pnpm
command -v yarn >/dev/null && PKG=yarn

run_pm(){
  case "$PKG" in
    pnpm) pnpm "$@" ;;
    yarn) yarn "$@" ;;
    *) npm "$@" ;;
  esac
}

[ -f package.json ] || die "package.json tidak ditemukan di $FRONTEND_DIR"

# Deteksi apakah source import framer-motion/lucide-react
USES_FM=$(grep -R "from[[:space:]]\+['\"]framer-motion['\"]" src 2>/dev/null | wc -l || true)
USES_LU=$(grep -R "from[[:space:]]\+['\"]lucide-react['\"]" src 2>/dev/null | wc -l || true)

# Pasang deps jika dipakai dan belum ada
need_dep(){
  node -e "try{const p=require('./package.json');process.exit((p.dependencies&&p.dependencies['$1'])?0:1)}catch(e){process.exit(1)}"
}

if [ "$USES_FM" -gt 0 ] && ! need_dep framer-motion; then
  say "  - Install framer-motion"
  run_pm add framer-motion
fi
if [ "$USES_LU" -gt 0 ] && ! need_dep lucide-react; then
  say "  - Install lucide-react"
  run_pm add lucide-react
fi

# Pastikan @vitejs/plugin-react ada (devDep)
node -e "try{const p=require('./package.json');process.exit((p.devDependencies&&p.devDependencies['@vitejs/plugin-react'])?0:1)}catch(e){process.exit(1)}" || {
  say "  - Install @vitejs/plugin-react (dev)"
  case "$PKG" in
    pnpm) pnpm add -D @vitejs/plugin-react ;;
    yarn) yarn add -D @vitejs/plugin-react ;;
    *)    npm i -D @vitejs/plugin-react ;;
  esac
}

# Pastikan base "/" di vite.config.(ts|js) (jika ada). Kalau tidak ada, buat.
if [ -f vite.config.ts ] || [ -f vite.config.js ]; then
  sed -i 's/base:[[:space:]]*["'\''][^"'\'']*["'\'']/base: "\/"/' vite.config.* 2>/dev/null || true
else
  say "  - Buat vite.config.js (base '/')"
  cat > vite.config.js <<'VITE'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  base: '/',
})
VITE
fi

# Install deps umum dan build
say "  - Install deps & build (Vite)"
case "$PKG" in
  pnpm) pnpm install --frozen-lockfile || pnpm install ;;
  yarn) yarn install --frozen-lockfile || yarn install ;;
  *)    npm ci || npm i ;;
esac
run_pm run build

# Publish ke webroot
sudo mkdir -p "$WEBROOT"
sudo rsync -a --delete dist/ "$WEBROOT"/
popd >/dev/null

# ===== 4) Restart container yang relevan (kalau ada Compose) =====
if [ -f "$COMPOSE_FILE" ]; then
  say "Restart stack via docker compose..."
  docker compose -f "$COMPOSE_FILE" up -d --no-deps streamlit-app caddy-rev tornado-web 2>/dev/null || true
fi

# ===== 5) Healthcheck sederhana =====
say "Self-test origin:"
curl -ks -o /dev/null -w "  /healthz        : %{http_code}\n"  http://127.0.0.1/healthz || true
curl -ks -o /dev/null -w "  /               : %{http_code}\n"  http://127.0.0.1/ || true
curl -ks -o /dev/null -w "  /monitor        : %{http_code}\n"  http://127.0.0.1/monitor || true
curl -ks -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASS}" -o /dev/null -w "  /monitor(+auth) : %{http_code}\n" http://127.0.0.1/monitor || true

say "Selesai patch Streamlit + Caddy + Frontend."

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$ROOT/docker-compose.yml"
STREAMLIT_APP="$ROOT/streamlit/app/app.py"
CADDYFILE="$ROOT/caddy/Caddyfile"
WEBROOT_VOL="monitoring_stack_webroot"

say()  { printf "\033[34m%s\033[0m\n" ">> $*"; }
ok()   { printf "\033[32m%s\033[0m\n" "✔ $*"; }
warn() { printf "\033[33m%s\033[0m\n" "WARN: $*"; }

# --- 1) Patch Streamlit app (perbaiki st.experimental_rerun + fitur log+download) ---
say "Patch Streamlit app..."
mkdir -p "$(dirname "$STREAMLIT_APP")"
cp -a "$STREAMLIT_APP" "$STREAMLIT_APP.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
cat > "$STREAMLIT_APP" <<'PY'
import os, json, time
from collections import deque
from typing import Deque, Dict, Any, List
import pandas as pd
import streamlit as st

# ====== Konfigurasi ======
LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
MAX_TAIL = int(os.getenv("EVE_MAX_LINES", "10000"))  # ambil N baris terakhir
PAGE_TITLE = "Suricata Monitoring"
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")

st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon="🛡️",
    layout="wide",
    menu_items={"About": "Monitoring Suricata – tugas akhir ID-NETWORKERS"}
)

# ====== Util ======
def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def parse_eve(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        try:
            obj = json.loads(ln)
            # flatten beberapa field umum
            flat = {
                "timestamp": obj.get("timestamp") or obj.get("@timestamp"),
                "event_type": obj.get("event_type"),
                "src_ip": obj.get("src_ip"),
                "src_port": obj.get("src_port"),
                "dest_ip": obj.get("dest_ip"),
                "dest_port": obj.get("dest_port"),
                "proto": obj.get("proto"),
                "alert_severity": (obj.get("alert") or {}).get("severity"),
                "alert_signature": (obj.get("alert") or {}).get("signature"),
            }
            rows.append({**flat, **obj})
        except Exception:
            # skip baris rusak
            continue
    if not rows:
        return pd.DataFrame()
    df = pd.json_normalize(rows, max_level=1)
    if "timestamp" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        except Exception:
            pass
    return df

@st.cache_data(ttl=5)
def load_df(max_tail: int, refresh_key: int) -> pd.DataFrame:
    lines = tail_lines(LOG_PATH, max_tail)
    return parse_eve(lines)

def force_rerun():
    # Streamlit >=1.27 pakai st.rerun(); fallback jika perlu
    try:
        st.rerun()
    except Exception:
        pass

# ====== UI ======
st.title("🛡️ Suricata Monitoring")
st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS** — dashboard ini menampilkan log Suricata (eve.json), grafik cepat, dan unduhan CSV/JSON.")

with st.sidebar:
    st.subheader("Demo credentials (Basic Auth di Caddy)")
    st.code("fox   / foxziemalam999\nadit  / aditidn123\nbebek / bebekcantik123", language="text")
    st.divider()
    st.write("Path aplikasi:", BASE_URL_PATH)
    max_tail = st.slider("Jumlah baris terakhir (tail)", 1000, 100000, MAX_TAIL, step=1000)
    auto = st.checkbox("Auto-refresh tiap 5 detik", value=False)
    if st.button("Refresh sekarang"):
        # bump session tick
        st.session_state["tick"] = st.session_state.get("tick", 0) + 1
        force_rerun()

# autorefresh sederhana
if auto:
    # tambahkan anchor supaya cache key berubah
    st.session_state["tick"] = int(time.time() // 5)

tick = st.session_state.get("tick", 0)
df = load_df(max_tail, tick)

tab_overview, tab_live, tab_download = st.tabs(["Overview", "Live Logs", "Unduh"])

with tab_overview:
    col1, col2, col3 = st.columns(3)
    col1.metric("Total event (tail)", len(df))
    if not df.empty:
        top_evt = df["event_type"].value_counts().head(1)
        col2.metric("Event teratas", f"{top_evt.index[0]} ({int(top_evt.iloc[0])})")
        alerts = df[df["event_type"] == "alert"]
        col3.metric("Alert (tail)", len(alerts))
    st.divider()

    if not df.empty:
        st.subheader("Distribusi event type")
        vc = df["event_type"].value_counts().reset_index()
        vc.columns = ["event_type", "count"]
        st.bar_chart(vc.set_index("event_type"))

        if "src_ip" in df.columns and "dest_ip" in df.columns:
            st.subheader("Top src → dest (count)")
            agg = (df.groupby(["src_ip","dest_ip"])
                     .size().reset_index(name="count")
                     .sort_values("count", ascending=False).head(20))
            st.dataframe(agg, use_container_width=True, height=320)

with tab_live:
    st.subheader("Live logs (tail)")
    if df.empty:
        st.info(f"Tidak ada data. Pastikan log tersedia di: `{LOG_PATH}`")
    else:
        # filter ringkas
        c1, c2, c3, c4 = st.columns([1,1,1,2])
        evt = c1.multiselect("event_type", sorted(df["event_type"].dropna().unique().tolist()))
        proto = c2.multiselect("proto", sorted(df["proto"].dropna().unique().tolist())) if "proto" in df.columns else []
        q = c3.text_input("cari IP / signature", "")
        n = c4.slider("tampilkan N baris terakhir", 100, min(5000, len(df)), min(1000, len(df)), 100)

        view = df.copy()
        if evt:   view = view[view["event_type"].isin(evt)]
        if proto: view = view[view["proto"].isin(proto)]
        if q:
            ql = q.lower()
            cols = [c for c in ["src_ip","dest_ip","alert_signature"] if c in view.columns]
            if cols:
                mask = False
                for c in cols:
                    mask = mask | view[c].astype(str).str.lower().str.contains(ql, na=False)
                view = view[mask]
        view = view.tail(n)

        st.dataframe(view, use_container_width=True, height=420)

with tab_download:
    st.subheader("Unduh data (tail yang sudah difilter manual di atas tidak ikut — paket penuh)")
    if df.empty:
        st.info("Belum ada data untuk diunduh.")
    else:
        # paket JSONL & CSV dari tail penuh
        jsonl = "\n".join(df.to_dict(orient="records").__iter__().__str__())  # placeholder; di bawah kita generate benar
        # generate JSONL dan CSV yang proper
        import io
        jsonl_io = io.StringIO()
        for _, row in df.iterrows():
            jsonl_io.write(json.dumps(row.to_dict(), default=str) + "\n")
        csv_io = io.StringIO()
        df.to_csv(csv_io, index=False)

        st.download_button("Unduh JSON Lines (eve_tail.jsonl)", data=jsonl_io.getvalue(), file_name="eve_tail.jsonl", mime="application/json")
        st.download_button("Unduh CSV (eve_tail.csv)", data=csv_io.getvalue(), file_name="eve_tail.csv", mime="text/csv")

# footer kecil
st.caption(f"Log path: `{LOG_PATH}` · baseUrlPath: `{BASE_URL_PATH}`")
PY

# --- 2) Pastikan Caddy mengirim user ke upstream (opsional) & route /monitor tidak strip_prefix ---
say "Terapkan header X-Remote-User (opsional) & route /monitor..."
cp -a "$CADDYFILE" "$CADDYFILE.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
# patch minimal: pastikan block /monitor ada & tidak strip_prefix; tambah header_up
if ! grep -q 'handle_path /monitor' "$CADDYFILE" && ! grep -q 'handle /monitor' "$CADDYFILE"; then
  warn "Tidak menemukan blok /monitor di Caddyfile. Lewati patch header."
else
  # sisipkan header_up jika belum ada
  if ! grep -q 'header_up X-Remote-User' "$CADDYFILE"; then
    sed -ri '/reverse_proxy[[:space:]]+streamlit-app:8501/{
      N
      s/reverse_proxy[^\n]*/& {\n    header_up X-Remote-User {http.auth.user.id}\n  }/
    }' "$CADDYFILE" || true
  fi
fi

# Format via container temp
docker run --rm -v "$ROOT/caddy:/etc/caddy" caddy:2 caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null || true

# --- 3) Rebuild & restart services yang perlu ---
say "Build & restart Streamlit + publish frontend ke webroot..."
docker compose -f "$COMPOSE" up -d streamlit-app frontend-builder caddy-rev
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc \
  'npm run build >/dev/null 2>&1 || npm run build; rm -rf /webroot/* && cp -r dist/* /webroot/'

# reload caddy
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

# --- 4) Self test origin ---
say "Self-test origin:"
curl -s -o /dev/null -w "  /healthz         : %{http_code}\n" http://127.0.0.1:8080/healthz || true
curl -s -o /dev/null -w "  /                : %{http_code}\n" http://127.0.0.1:8080/ || true
curl -s -o /dev/null -w "  /monitor         : %{http_code}\n" http://127.0.0.1:8080/monitor || true
curl -s -o /dev/null -w "  /monitor(+auth)  : %{http_code}\n" -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor || true

ok "Selesai patch Streamlit + Caddy + Frontend."
#!/usr/bin/env bash
# fix_streamlit_live.sh
# Patch Streamlit app agar live & kompatibel (st.rerun), plus dashboard/log/download.
set -euo pipefail

# --- Lokasi proyek (jalankan dari folder cloudflared) ---
BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"
APP_HOST="${APP_HOST:-$BASE/streamlit/app/app.py}"
APP_IN_CONTAINER="/app/app/app.py"
SERVICE="streamlit-app"

die(){ echo "ERR: $*" >&2; exit 1; }

[ -f "$COMPOSE" ] || die "docker-compose.yml tidak ditemukan di: $COMPOSE (jalankan dari folder cloudflared)."

TS="$(date +%Y%m%d_%H%M%S)"

echo ">> Pastikan stack hidup..."
docker compose -f "$COMPOSE" up -d $SERVICE >/dev/null

# --- Backup & tulis app.py di host (jika ada) ---
if [ -f "$APP_HOST" ]; then
  cp -a "$APP_HOST" "$APP_HOST.bak.$TS"
  echo ">> Backup host: $APP_HOST.bak.$TS"
else
  echo "WARN: Source host $APP_HOST tidak ada. Tetap akan injek ke container."
fi

# --- Konten app.py baru ---
read -r -d '' PYCODE <<'PY'
# app.py — Monitoring Suricata (ID-NETWORKERS)
import os, json, io, time, math, pathlib, sys
from collections import deque
import pandas as pd
import streamlit as st

# Altair opsional; fallback ke st.* chart
HAS_ALTAIR = True
try:
    import altair as alt   # type: ignore
except Exception:
    HAS_ALTAIR = False

st.set_page_config(page_title="Monitoring Suricata", layout="wide")

st.title("Monitoring Suricata")
st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

# ---------- Konfigurasi ----------
EVE_PATH = os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
DEFAULT_LINES = int(os.environ.get("EVE_TAIL_LINES", "1500"))

# ---------- Util ----------
def force_rerun():
    try:
        st.rerun()
    except Exception:
        pass

def _tail_bytes(fp, max_lines=DEFAULT_LINES, chunk=1<<16):
    """
    Tail efisien: baca dari belakang sampai dapat ~max_lines baris JSON.
    """
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    buf = b""
    lines = []
    pos = size
    while pos > 0 and len(lines) <= max_lines:
        read = min(chunk, pos)
        pos -= read
        fp.seek(pos)
        buf = fp.read(read) + buf
        # split ke baris
        parts = buf.split(b"\n")
        buf = parts[0]  # sisa head
        lines = parts[1:] + lines
    # gabungkan sisa head bila valid json line
    if buf.strip():
        lines = [buf] + lines
    # ambil terakhir max_lines
    return lines[-max_lines:]

def load_eve(path: str, max_lines: int):
    p = pathlib.Path(path)
    if not p.exists():
        return pd.DataFrame(), {"exists": False, "size": 0, "path": path}
    size = p.stat().st_size
    objs = []
    with p.open("rb") as f:
        raw_lines = _tail_bytes(f, max_lines=max_lines)
        for b in raw_lines:
            if not b.strip():
                continue
            try:
                o = json.loads(b.decode("utf-8", "ignore"))
                objs.append(o)
            except Exception:
                # abaikan baris rusak
                pass
    df = pd.json_normalize(objs, max_level=2) if objs else pd.DataFrame()
    meta = {"exists": True, "size": size, "path": str(p), "rows": len(df)}
    return df, meta

def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    if df.empty: 
        return b""
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")

# ---------- Sidebar ----------
with st.sidebar:
    st.subheader("Kontrol")
    eve_path_input = st.text_input("Lokasi eve.json", value=EVE_PATH, help="Default: /var/log/suricata/eve.json")
    lines = st.slider("Tail baris (terakhir)", 100, 10000, DEFAULT_LINES, step=100)
    colA, colB = st.columns(2)
    with colA:
        auto = st.checkbox("Auto-refresh", value=False)
    with colB:
        interval = st.number_input("Detik", min_value=2, max_value=60, value=5, step=1)

    st.markdown("---")
    st.caption("🔐 Akses dilindungi Basic Auth di reverse proxy (Caddy).")

# ---------- Muat Data ----------
df, meta = load_eve(eve_path_input, max_lines=lines)

if not meta.get("exists", False):
    st.error(f"File tidak ditemukan: **{eve_path_input}**")
else:
    st.info(f"File: `{meta['path']}` • ukuran: {meta['size']:,} bytes • baris dimuat: {meta.get('rows',0)}")

# ---------- Tabs ----------
tab_dash, tab_logs, tab_dl = st.tabs(["📊 Dashboard", "📜 Logs", "⬇️ Download"])

with tab_dash:
    if df.empty:
        st.warning("Belum ada data.")
    else:
        # Timestamp normalisasi
        tscol = None
        for c in ["timestamp", "event_type.ts", "@timestamp"]:
            if c in df.columns:
                tscol = c; break
        if tscol:
            try:
                dt = pd.to_datetime(df[tscol], errors="coerce")
                df["_minute"] = dt.dt.floor("min")
            except Exception:
                df["_minute"] = pd.NaT
        else:
            df["_minute"] = pd.NaT

        # Hitung hanya alert
        if "event_type" in df.columns:
            alerts = df[df["event_type"] == "alert"].copy()
        else:
            alerts = df.copy()

        # Top signature
        sig_col = None
        for c in ["alert.signature", "alert.signature_id", "alert.signature.keyword"]:
            if c in df.columns:
                sig_col = c; break

        c1, c2, c3 = st.columns([2,2,1])
        with c1:
            if "_minute" in df.columns and df["_minute"].notna().any():
                agg = alerts.groupby("_minute").size().reset_index(name="count")
                st.caption("Alert per menit")
                if HAS_ALTAIR:
                    import altair as alt
                    ch = alt.Chart(agg).mark_line(point=True).encode(
                        x="{}_minute:T".format(""),
                        y="count:Q",
                        tooltip=["_minute:T","count:Q"]
                    ).properties(height=220)
                    st.altair_chart(ch, use_container_width=True)
                else:
                    agg = agg.set_index("_minute")
                    st.line_chart(agg["count"])
            else:
                st.info("Kolom timestamp tidak tersedia.")

        with c2:
            if sig_col:
                top = (alerts.groupby(sig_col).size()
                              .reset_index(name="count")
                              .sort_values("count", ascending=False).head(10))
                st.caption("Top 10 Signature")
                if HAS_ALTAIR:
                    ch = alt.Chart(top).mark_bar().encode(
                        x="count:Q", y=alt.Y(f"{sig_col}:N", sort="-x"),
                        tooltip=[sig_col,"count"]
                    ).properties(height=220)
                    st.altair_chart(ch, use_container_width=True)
                else:
                    st.bar_chart(top.set_index(sig_col)["count"])
            else:
                st.info("Kolom signature tidak tersedia.")

        with c3:
            sev_col = "alert.severity" if "alert.severity" in alerts.columns else None
            if sev_col:
                sev = (alerts.groupby(sev_col).size()
                              .reset_index(name="count")
                              .sort_values(sev_col))
                st.metric("Total Alert", int(sev["count"].sum()))
                st.dataframe(sev, use_container_width=True, height=220)
            else:
                st.metric("Total Event", int(len(df)))

with tab_logs:
    st.caption("Tail log (terbaru di bawah)")
    if df.empty:
        st.info("Tidak ada data untuk ditampilkan.")
    else:
        # Pilih kolom ringkas
        cols_pref = [c for c in ["timestamp","event_type","src_ip","src_port","dest_ip","dest_port","proto",
                                 "alert.signature","alert.severity","http.hostname","dns.rrname"] if c in df.columns]
        view = df[cols_pref] if cols_pref else df
        st.dataframe(view.tail(500), use_container_width=True, height=420)

with tab_dl:
    st.caption("Unduh data terakhir yang dimuat (tail)")
    c1, c2 = st.columns(2)
    with c1:
        st.download_button("⬇️ Download CSV", data=df_to_csv_bytes(df), file_name="eve_tail.csv", mime="text/csv", disabled=df.empty)
    with c2:
        raw = b""
        try:
            # Ambil raw tail JSON Lines utk download cepat
            p = pathlib.Path(eve_path_input)
            if p.exists():
                with p.open("rb") as f:
                    raw_lines = _tail_bytes(f, max_lines=lines)
                raw = b"\n".join(raw_lines)
        except Exception:
            pass
        st.download_button("⬇️ Download JSON (tail)", data=raw, file_name="eve_tail.json", mime="application/json", disabled=(raw==b""))

# ---------- Auto refresh ----------
if auto:
    time.sleep(int(interval))
    force_rerun()
PY

# --- Tulis ke host (jika path ada) ---
if [ -d "$(dirname "$APP_HOST")" ]; then
  echo ">> Tulis app.py ke host: $APP_HOST"
  printf '%s\n' "$PYCODE" > "$APP_HOST"
else
  echo "WARN: Direktori host untuk $APP_HOST tidak ada, lewati penulisan host."
fi

# --- Injek langsung ke container agar efeknya instan ---
CID="$(docker compose -f "$COMPOSE" ps -q $SERVICE || true)"
if [ -n "$CID" ]; then
  echo ">> Injek app.py ke container ($SERVICE)..."
  docker compose -f "$COMPOSE" exec -T $SERVICE sh -lc "cat > '$APP_IN_CONTAINER' <<'PY'
$PYCODE
PY"
else
  echo "WARN: Container $SERVICE belum aktif; akan dihidupkan pada langkah berikut."
fi

# --- Restart service biar pasti reload ---
echo ">> Restart $SERVICE ..."
docker compose -f "$COMPOSE" restart $SERVICE >/dev/null

# --- Tes ringkas: endpoint Streamlit (via Caddy sudah diatur /monitor) tetap di-serve oleh Streamlit ---
echo ">> DONE. Buka dashboard di: /monitor"
echo "   - Tab Dashboard: grafik alert/minute, top signature"
echo "   - Tab Logs: tail 500 baris terakhir"
echo "   - Tab Download: CSV & JSON (tail)"
echo "   - Sidebar: auto-refresh live (2–60 detik)"
#!/usr/bin/env bash
# hotfix_streamlit_and_frontend.sh
set -euo pipefail

BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"
SVC_S="streamlit-app"
SVC_F="frontend-builder"
APPDIR_CONT="/app/app"
APP_CONT="$APPDIR_CONT/app.py"

echo ">> Compose: $COMPOSE"
[ -f "$COMPOSE" ] || { echo "ERR: compose file tidak ketemu"; exit 1; }

echo ">> Pastikan stack hidup..."
docker compose -f "$COMPOSE" up -d >/dev/null

CID_S="$(docker compose -f "$COMPOSE" ps -q $SVC_S)"
CID_F="$(docker compose -f "$COMPOSE" ps -q $SVC_F)"
[ -n "$CID_S" ] || { echo "ERR: container $SVC_S belum jalan"; exit 1; }
[ -n "$CID_F" ] || { echo "ERR: container $SVC_F belum jalan"; exit 1; }

###############################################################################
# STREAMLIT: fix import, package, live tail, dan experimental_rerun
###############################################################################
echo ">> Patch Streamlit: jadikan package + inject live tail + fix rerun..."
docker compose -f "$COMPOSE" exec -T "$SVC_S" sh -lc "
  set -e
  test -f '$APP_CONT' || { echo 'ERR: $APP_CONT tidak ada'; exit 1; }
  cp -a '$APP_CONT' '${APP_CONT}.bak.$(date +%Y%m%d_%H%M%S)' || true
  # jadikan /app/app sebagai package
  [ -f '$APPDIR_CONT/__init__.py' ] || : > '$APPDIR_CONT/__init__.py'
  # tulis helper live tail (quoted supaya tidak diexpand shell)
  cat > '$APPDIR_CONT/_live_tail_patch.py' <<'PY'
import os, time, json, pathlib
import streamlit as st
from collections import deque

EVE_PATH = os.environ.get('EVE_PATH', '/var/log/suricata/eve.json')

def _read_last_lines(path, n=300):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    dq = deque(maxlen=n)
    with p.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if s:
                dq.append(s)
    return list(dq)

def render_live():
    st.set_page_config(page_title='Suricata Monitor', layout='wide')
    st.header('Monitoring Suricata')
    st.caption('Untuk menyelesaikan tugas akhir dari ID-NETWORKERS')

    with st.expander('Kredensial Akses (Basic Auth via Caddy)'):
        st.code('fox / foxziemalam999\\nadit / aditidn123\\nbebek / bebekcantik123', language='bash')
        st.warning('Jangan tampilkan ini di produksi.')

    colA, colB = st.columns([3,1])
    with colB:
        auto = st.toggle('Live refresh', value=True)
        every = st.number_input('Refresh (detik)', 1, 30, 2)
        limit = st.slider('Baris terakhir', 50, 2000, 300, 50)
        q = st.text_input('Filter (substring)', '', placeholder='event_type:alert atau src_ip=192.168.1.10')
    with colA:
        st.markdown(f'**File:** `{EVE_PATH}`')

    # ambil data
    raw_lines = _read_last_lines(EVE_PATH, n=limit)
    rows = []
    alerts = 0
    for s in raw_lines:
        try:
            obj = json.loads(s)
            if obj.get('event_type') == 'alert':
                alerts += 1
            rows.append(obj)
        except Exception:
            rows.append({'_raw': s})

    # filter sederhana (substring ke JSON dump)
    if q:
        ql = q.lower()
        filtered = []
        for r in rows:
            try:
                hay = json.dumps(r, ensure_ascii=False).lower()
            except Exception:
                hay = str(r).lower()
            if ql in hay:
                filtered.append(r)
        rows = filtered

    # metrik ringkas
    c1, c2, c3 = st.columns(3)
    c1.metric('Events ditampilkan', len(rows))
    c2.metric('Alerts', alerts)
    c3.metric('Last refresh', time.strftime('%H:%M:%S'))

    # tampilkan tabel
    try:
        import pandas as pd
        df = pd.json_normalize(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        # download
        st.download_button('Unduh CSV', data=df.to_csv(index=False), file_name='eve_subset.csv', mime='text/csv')
        st.download_button('Unduh JSONL', data='\\n'.join(json.dumps(r, ensure_ascii=False) for r in rows),
                           file_name='eve_subset.jsonl', mime='application/json')
    except Exception:
        st.write(rows)

    if auto:
        time.sleep(every)
        st.rerun()
PY

  # ganti import jadi lokal
  if grep -q '^from app\\._live_tail_patch import render_live' '$APP_CONT'; then
    sed -ri 's|^from app\\._live_tail_patch import render_live|from _live_tail_patch import render_live|' '$APP_CONT'
  fi
  # jika belum ada import, sisipkan di baris pertama
  if ! grep -q 'from _live_tail_patch import render_live' '$APP_CONT'; then
    sed -ri '1s|^|from _live_tail_patch import render_live\\n|' '$APP_CONT'
  fi
  # bersihkan experimental_rerun
  sed -ri '/st\\.experimental_rerun[[:space:]]*$/d' '$APP_CONT'
  sed -ri 's/st\\.experimental_rerun\\(/st.rerun(/g' '$APP_CONT'

  # pastikan ada panggilan render_live() di akhir file (tanpa dobel)
  if ! grep -q 'render_live\\(\\)' '$APP_CONT'; then
    printf '\\nif __name__ == \"__main__\":\\n    render_live()\\n' >> '$APP_CONT'
  fi
"
echo ">> Restart Streamlit..."
docker compose -f "$COMPOSE" restart "$SVC_S" >/dev/null

###############################################################################
# FRONTEND: sinkronkan App.jsx (punyamu) + CSS ciamik + build + publish
###############################################################################
echo ">> Patch Frontend (App.jsx + index.css) & build..."
docker compose -f "$COMPOSE" exec -T "$SVC_F" sh -lc "
  set -e
  cd /app

  # Tulis index.css (ciamik)
  cat > src/index.css <<'CSS'
:root{--bg:#0b1220;--fg:#e9eefc;--muted:#9fb2d9;--card:#121b31;--cta:#3b82f6;--ctaHover:#2563eb}
*{box-sizing:border-box}html,body,#root{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif}
.hero{display:flex;flex-direction:column;min-height:100%}
.topbar{position:sticky;top:0;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(6px)}
.brand{padding:14px 20px;font-weight:700;letter-spacing:.4px}
.wrap{max-width:920px;margin:clamp(32px,7vh,72px) auto;padding:0 20px;text-align:center}
h1{font-size:clamp(28px,6vw,48px);margin:0 0 10px;line-height:1.1}
.tagline{color:var(--muted);font-size:clamp(14px,2.5vw,18px);margin:0 auto 26px}
.bullets{list-style:none;padding:0;margin:10px auto 28px;display:inline-grid;gap:10px}
.bullets li{background:var(--card);border:1px solid rgba(255,255,255,.06);padding:10px 14px;border-radius:14px;color:#cfe0ff}
.cta{display:inline-block;margin-top:4px;background:var(--cta);color:#fff;text-decoration:none;padding:12px 18px;border-radius:12px;font-weight:700}
.cta:hover{background:var(--ctaHover)}
.foot{margin-top:auto;padding:20px;color:#91a7d7;opacity:.9;text-align:center;font-size:13px;border-top:1px dashed rgba(255,255,255,.08)}
/* responsive tweaks */
@media (max-width:640px){.brand{padding:12px 16px}.wrap{padding:0 14px}.bullets{grid-template-columns:1fr}}
CSS

  # Pastikan main.jsx import CSS
  if ! grep -q 'index.css' src/main.jsx 2>/dev/null; then
    sed -ri '1s|^|import \"./index.css\";\\n|' src/main.jsx
  fi

  # Pakai App.jsx yang kamu kirim
  cat > src/App.jsx <<'JS'
YOUR_APP_JS_WILL_BE_INJECTED_HERE
JS

  # deps wajib untuk App.jsx
  if ! node -e 'require.resolve(\"framer-motion\")' >/dev/null 2>&1; then npm install framer-motion@latest; fi
  if ! node -e 'require.resolve(\"lucide-react\")' >/dev/null 2>&1; then npm install lucide-react@latest; fi

  # build & publish
  (npm ci || npm install)
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
"

# sisipkan konten App.jsx user (safe replace placeholder)
APP_JS_ESCAPED="$(python3 - <<'PY'
import sys, json
js = sys.stdin.read()
print(js)
PY
<<'APPJS'
import React from "react";
import { motion } from "framer-motion";
import { Activity, LineChart, ShieldAlert, Cloud, Download, Filter, Box, Lock, TerminalSquare, ArrowRight, Github, KeyRound, Cog, ExternalLink, CheckCircle2, Copy } from "lucide-react";

export default function App() {
  const creds = [
    { user: "fox", pass: "foxziemalam999" },
    { user: "adit", pass: "aditidn123" },
    { user: "bebek", pass: "bebekcantik123" },
  ];

  const copy = (text) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 selection:bg-emerald-500/30 selection:text-emerald-200">
      <div className="fixed inset-0 -z-10">
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_-10%,rgba(16,185,129,0.15),rgba(0,0,0,0))]" />
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_110%,rgba(99,102,241,0.12),rgba(0,0,0,0))]" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
      </div>

      <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/40 border-b border-white/5">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="size-8 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30">
              <ShieldAlert className="size-5 text-emerald-400" />
            </div>
            <span className="font-semibold tracking-tight">Suricata Monitor</span>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm text-zinc-300">
            <a href="#fitur" className="hover:text-white">Fitur</a>
            <a href="#teknologi" className="hover:text-white">Teknologi</a>
            <a href="#demo" className="hover:text-white">Demo</a>
            <a href="#faq" className="hover:text-white">FAQ</a>
          </nav>
          <div className="flex items-center gap-3">
            <a href="/monitor" className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium bg-emerald-500 hover:bg-emerald-400 text-zinc-950 transition-colors">
              Masuk Dashboard <ArrowRight className="size-4" />
            </a>
          </div>
        </div>
      </header>

      <section className="relative">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-10 pt-16 pb-10">
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
              <h1 className="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">
                Monitoring <span className="text-emerald-400">Suricata</span>
              </h1>
              <p className="mt-4 text-lg text-zinc-300">
                Untuk menyelesaikan tugas akhir dari <b className="text-white">ID-NETWORKERS</b>. Dashboard menampilkan log <code className="text-emerald-300">eve.json</code>, grafik singkat, dan unduhan CSV/JSON.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <a href="/monitor" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium bg-emerald-500 hover:bg-emerald-400 text-zinc-950 transition-colors">
                  <TerminalSquare className="size-5" /> Masuk ke Dashboard
                </a>
                <a href="/docs" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium border border-white/10 hover:border-white/20">
                  <ExternalLink className="size-5" /> Dokumentasi
                </a>
                <a href="https://github.com/" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium border border-white/10 hover:border-white/20">
                  <Github className="size-5" /> Source
                </a>
              </div>
              <div className="mt-10 grid grid-cols-3 gap-4 max-w-lg">
                {[
                  { icon: Activity, label: "Events/min", value: "~1.2k" },
                  { icon: ShieldAlert, label: "Alerts", value: "~230" },
                  { icon: LineChart, label: "Throughput", value: "~180 Mbps" },
                ].map((s) => (
                  <div key={s.label} className="rounded-2xl border border-white/10 p-4">
                    <div className="flex items-center gap-2 text-zinc-400 text-xs">
                      {React.createElement(s.icon, { className: "size-4 text-emerald-400" })}
                      {s.label}
                    </div>
                    <div className="mt-1 text-2xl font-semibold">{s.value}</div>
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.1 }}>
              <div className="relative rounded-3xl border border-white/10 bg-zinc-900/60 backdrop-blur p-4 lg:p-6 shadow-2xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-zinc-400">
                    <div className="size-2 rounded-full bg-rose-400" />
                    <div className="size-2 rounded-full bg-amber-400" />
                    <div className="size-2 rounded-full bg-emerald-400" />
                    <span className="ml-2">tail -f /var/log/suricata/eve.json</span>
                  </div>
                  <span className="text-xs text-zinc-400">Live</span>
                </div>
                <pre className="mt-4 h-72 overflow-auto rounded-2xl bg-black/60 p-4 text-xs leading-relaxed text-emerald-200/90">
{`{\"timestamp\":\"2025-08-11T14:22:10Z\",\"event_type\":\"alert\",\"src_ip\":\"192.168.10.5\",\"dest_ip\":\"10.10.10.12\",\"alert\":{\"signature\":\"ET WEB_SERVER Possible SQLi UNION SELECT\",\"severity\":2}}
{\"timestamp\":\"2025-08-11T14:22:11Z\",\"event_type\":\"dns\",\"query\":\"suspicious.example\",\"rrtype\":\"A\",\"rcode\":\"NOERROR\"}
{\"timestamp\":\"2025-08-11T14:22:12Z\",\"event_type\":\"flow\",\"app_proto\":\"http\",\"bytes_toserver\":9831,\"bytes_toclient\":12044}
`}
                </pre>
                <div className="mt-3 flex items-center justify-between text-xs text-zinc-400">
                  <div className="flex items-center gap-3">
                    <div className="inline-flex items-center gap-1"><Filter className="size-4 text-emerald-400" /> filter: <code>event_type:alert</code></div>
                    <div className="inline-flex items-center gap-1"><Download className="size-4 text-emerald-400" /> export: CSV · JSONL</div>
                  </div>
                  <div className="inline-flex items-center gap-1"><Cloud className="size-4 text-emerald-400" /> Cloudflared Tunnel</div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section id=\"fitur\" className=\"py-12 sm:py-16\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Fitur\" subtitle=\"Semua yang kamu butuhkan untuk observasi cepat\" />
          <div className=\"mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3\">
            <Feature icon={Filter} title=\"Live tail + filter\" desc=\"Streaming eve.json dengan query sederhana (event_type, src_ip, signature).\" />
            <Feature icon={LineChart} title=\"Grafik event & alert\" desc=\"Sparkline & mini chart untuk tren menit-an atau jam-an.\" />
            <Feature icon={Download} title=\"Unduh CSV & JSONL\" desc=\"Ambil subset data untuk analisis lanjutan di Python/R/SIEM.\" />
            <Feature icon={Lock} title=\"Basic Auth\" desc=\"Caddy reverse proxy dengan kredensial demo untuk akses cepat.\" />
            <Feature icon={Box} title=\"Ringan\" desc=\"Vite + React (landing), Streamlit 1.37 (Python 3.11) untuk UI log.\" />
            <Feature icon={Cloud} title=\"Tunnel\" desc=\"Expose lokal aman via Cloudflared Tunnel tanpa fixed IP.\" />
          </div>
        </div>
      </section>

      <section id=\"teknologi\" className=\"py-12 sm:py-16 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Teknologi\" subtitle=\"Komponen utama deployment\" />
          <div className=\"mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4\">
            {[
              { name: \"Streamlit 1.37\", icon: TerminalSquare },
              { name: \"Caddy Reverse Proxy\", icon: Lock },
              { name: \"Vite + React\", icon: Box },
              { name: \"Cloudflared Tunnel\", icon: Cloud },
            ].map((t) => (
              <div key={t.name} className=\"rounded-2xl border border-white/10 p-5 flex items-center gap-3\">
                {React.createElement(t.icon, { className: \"size-6 text-emerald-400\" })}
                <div>
                  <div className=\"font-medium\">{t.name}</div>
                  <div className=\"text-xs text-zinc-400\">Production-ready</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id=\"demo\" className=\"py-12 sm:py-16\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Demo Credentials\" subtitle=\"Gunakan saat diminta Basic Auth (Caddy).\" />
          <div className=\"mt-6 grid gap-4 lg:grid-cols-2\">
            <div className=\"rounded-2xl border border-white/10 p-6\">
              <div className=\"text-sm text-zinc-400\">Akun Demo</div>
              <div className=\"mt-3 divide-y divide-white/5\">
                {[
                  {user:'fox',pass:'foxziemalam999'},
                  {user:'adit',pass:'aditidn123'},
                  {user:'bebek',pass:'bebekcantik123'}
                ].map((c)=>(
                  <div key={c.user} className=\"py-3 flex items-center justify-between\">
                    <div>
                      <div className=\"font-mono text-sm\">{c.user}</div>
                      <div className=\"text-xs text-zinc-400\">{c.pass}</div>
                    </div>
                    <button onClick={()=>navigator.clipboard.writeText(`${c.user}:${c.pass}`)} className=\"inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-1.5 text-xs hover:border-white/20\">
                      <Copy className=\"size-3.5\" /> salin
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className=\"rounded-2xl border border-white/10 p-6 bg-gradient-to-b from-white/5 to-transparent\">
              <div className=\"text-sm text-zinc-400\">Contoh Konfigurasi Caddy (Basic Auth)</div>
              <pre className=\"mt-3 text-xs bg-black/50 rounded-xl p-4 overflow-auto\">{`# Caddyfile
:80 {
  handle_path /monitor* {
    basic_auth { ... }
    reverse_proxy streamlit-app:8501
  }
}`}</pre>
            </div>
          </div>
        </div>
      </section>

      <section id=\"faq\" className=\"py-12 sm:py-16 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"FAQ\" subtitle=\"Pertanyaan umum terkait setup\" />
          <div className=\"mt-6 grid gap-4 lg:grid-cols-2\">
            <Faq q=\"Apakah butuh VPS?\" a=\"Tidak wajib. Bisa expose lokal via Cloudflared Tunnel.\" />
            <Faq q=\"Apakah data bisa di-export?\" a=\"Ya, unduh CSV/JSONL dari dashboard.\" />
            <Faq q=\"Autentikasi seperti apa?\" a=\"Basic Auth di layer proxy (Caddy).\" />
            <Faq q=\"Seberapa ringan?\" a=\"Landing Vite + React, backend Streamlit.\" />
          </div>
        </div>
      </section>

      <footer className=\"mt-10 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <div className=\"py-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-zinc-400\">
            <div className=\"flex items-center gap-2\">
              <CheckCircle2 className=\"size-4 text-emerald-400\" />
              <span>© {new Date().getFullYear()} Suricata Monitor • ID-NETWORKERS TA</span>
            </div>
            <div className=\"flex items-center gap-5\">
              <a href=\"/monitor\" className=\"hover:text-white inline-flex items-center gap-1\"><TerminalSquare className=\"size-4\" /> Dashboard</a>
              <a href=\"/docs\" className=\"hover:text-white inline-flex items-center gap-1\"><ExternalLink className=\"size-4\" /> Docs</a>
              <a href=\"https://github.com/\" className=\"hover:text-white inline-flex items-center gap-1\"><Github className=\"size-4\" /> GitHub</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function SectionTitle({ title, subtitle }) {
  return (
    <div className=\"max-w-2xl\">
      <h2 className=\"text-2xl font-semibold\">{title}</h2>
      <p className=\"mt-1 text-zinc-400\">{subtitle}</p>
    </div>
  );
}

function Feature({ icon: Icon, title, desc }) {
  return (
    <div className=\"rounded-2xl border border-white/10 p-5\">
      <div className=\"flex items-center gap-3\">
        <div className=\"size-9 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30\">
          <Icon className=\"size-5 text-emerald-400\" />
        </div>
        <div>
          <div className=\"font-medium\">{title}</div>
          <div className=\"text-sm text-zinc-400\">{desc}</div>
        </div>
      </div>
    </div>
  );
}

function Faq({ q, a }) {
  return (
    <details className=\"rounded-2xl border border-white/10 p-5 group open:bg-white/[0.02]\">
      <summary className=\"cursor-pointer list-none flex items-center justify-between\">
        <span className=\"font-medium\">{q}</span>
        <span className=\"text-zinc-400 group-open:rotate-90 transition-transform\">›</span>
      </summary>
      <p className=\"mt-3 text-sm text-zinc-300\">{a}</p>
    </details>
  );
}
APPJS
)"
# inject App.jsx content
docker compose -f "$COMPOSE" exec -T "$SVC_F" sh -lc "perl -0777 -pe 's#YOUR_APP_JS_WILL_BE_INJECTED_HERE#\${APP_JS_ESCAPED}#s' -i /app/src/App.jsx" >/dev/null 2>&1 || true

echo ">> Reload Caddy..."
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

echo ">> Tes origin:"
curl -sI http://127.0.0.1:8080/healthz | head -n1 || true
curl -sI http://127.0.0.1:8080/        | head -n1 || true
curl -sI http://127.0.0.1:8080/monitor | head -n1 || true

echo ">> Done."
#!/usr/bin/env bash
set -euo pipefail

# --- (opsional) path sumber kode lama untuk di-copy ---
SOURCE_TORNADO="${SOURCE_TORNADO:-}"
SOURCE_STREAMLIT="${SOURCE_STREAMLIT:-}"
SOURCE_FRONTEND="${SOURCE_FRONTEND:-}"

say(){ printf "\033[1;32m[+] %s\033[0m\n" "$*"; }
warn(){ printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err(){ printf "\033[1;31m[!] %s\033[0m\n" "$*"; }

backup_if_exists() {
  local p="$1"
  if [ -e "$p" ]; then
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    mv "$p" "${p}.bak_${ts}"
    warn "Backup ${p} -> ${p}.bak_${ts}"
  fi
}

mkdir -p caddy cloudflared backend/app streamlit/app suricata frontend/src

# ---- .env (COOKIE_SECRET + iface wlan0 utk Suricata) ----
if [ ! -f .env ]; then
  say "Generate .env"
  COOKIE_SECRET="$(head -c 32 /dev/urandom | base64)"
  cat > .env <<EOF
# Suricata interface host
SURI_IFACE=wlan0
# Tornado secure cookie secret (jaga)
COOKIE_SECRET=${COOKIE_SECRET}
EOF
else
  warn ".env sudah ada, tidak ditimpa"
fi

# ---- docker-compose.yml ----
backup_if_exists docker-compose.yml
cat > docker-compose.yml <<'YAML'
version: "3.9"
name: monitoring_stack

volumes:
  webroot: {}
  suri_logs:
  suri_etc:

networks:
  webnet:
    driver: bridge

services:
  frontend-builder:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    command: sh -lc "npm ci && npm run build && rm -rf /webroot/* && cp -r dist/* /webroot/ && tail -f /dev/null"
    volumes:
      - webroot:/webroot
    networks: [webnet]
    restart: unless-stopped

  caddy-rev:
    image: caddy:2
    depends_on:
      - frontend-builder
      - tornado-web
      - streamlit-app
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - webroot:/srv/www:ro
    networks: [webnet]
    ports:
      - "8080:80"
    restart: unless-stopped

  tornado-web:
    build:
      context: ./backend
      dockerfile: Dockerfile
    networks: [webnet]
    expose:
      - "8080"
    env_file: [.env]
    restart: unless-stopped

  streamlit-app:
    build:
      context: ./streamlit
      dockerfile: Dockerfile
    command: >
      streamlit run /app/app/app.py
      --server.address=0.0.0.0
      --server.port=8501
      --server.baseUrlPath=/monitor
    networks: [webnet]
    expose:
      - "8501"
    volumes:
      - suri_logs:/var/log/suricata:ro
    restart: unless-stopped

  # Cloudflared pakai host network -> Service URL = http://localhost:8080
  cloudflared:
    image: cloudflare/cloudflared:latest
    depends_on:
      - caddy-rev
    network_mode: host
    volumes:
      - ./cloudflared:/home/nonroot/.cloudflared
    command: tunnel --no-autoupdate --config /home/nonroot/.cloudflared/config.yml run
    restart: unless-stopped

  # Suricata host-mode, capture wlan0 (default)
  suricata:
    build:
      context: ./suricata
      dockerfile: Dockerfile.suricata
    network_mode: host
    cap_add: [ "NET_ADMIN", "NET_RAW" ]
    env_file: [.env]
    environment:
      - SURI_IFACE=${SURI_IFACE:-wlan0}
    volumes:
      - suri_logs:/var/log/suricata
      - suri_etc:/etc/suricata
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
    command: ["/entrypoint.sh"]
    restart: unless-stopped
YAML

# ---- Caddyfile (login page via Tornado, cookie gate ke /monitor) ----
backup_if_exists caddy/Caddyfile
cat > caddy/Caddyfile <<'CADDY'
{
  auto_https off
  servers :80 {
    protocols h1 h2c
  }
}

:80 {
  # API -> Tornado
  handle_path /api/* {
    reverse_proxy tornado-web:8080
  }

  # Auth pages -> Tornado
  handle_path /login* {
    reverse_proxy tornado-web:8080
  }
  handle_path /logout* {
    reverse_proxy tornado-web:8080
  }

  # Gate Streamlit di /monitor pakai cookie "session="
  @authed header_regexp hasSess Cookie session=.+

  handle /monitor* {
    # kalau ada cookie "session", lolos ke Streamlit
    handle @authed {
      uri strip_prefix /monitor
      reverse_proxy streamlit-app:8501
    }
    # kalau belum login => redirect ke /login
    handle {
      redir /login?next=/monitor 302
    }
  }

  # Static React (default)
  handle {
    root * /srv/www
    encode zstd gzip
    try_files {path} /index.html
    file_server
  }
}
CADDY

# ---- Cloudflared config (origin ke localhost:8080 + fallback 404) ----
if [ ! -f cloudflared/config.yml ]; then
  cat > cloudflared/config.yml <<'YAML'
tunnel: REPLACE_TUNNEL_ID
credentials-file: /home/nonroot/.cloudflared/REPLACE_TUNNEL_ID.json

ingress:
  - service: http://localhost:8080
  - service: http_status:404
YAML
  warn "Edit cloudflared/config.yml dan ganti REPLACE_TUNNEL_ID dengan Tunnel ID-mu."
else
  warn "cloudflared/config.yml sudah ada, tidak ditimpa"
fi

# ---- Tornado (login page + secure cookie) ----
backup_if_exists backend/Dockerfile
cat > backend/Dockerfile <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir tornado==6.4.1
COPY app /app/app
EXPOSE 8080
CMD ["python", "-m", "app.main"]
DOCKER

backup_if_exists backend/app/main.py
cat > backend/app/main.py <<'PY'
import os, urllib.parse
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, authenticated

COOKIE_SECRET = os.getenv("COOKIE_SECRET", "dev-insecure")
LOGIN_URL = "/login"

USERS = {
    "fox": "foxzie900",
    "bebek": "bebekcantik321",
}

HTML_LOGIN = """<!doctype html>
<html><head><meta charset="utf-8">
<title>Login</title>
<style>body{font-family:sans-serif;background:#0b1020;color:#e6f;display:flex;align-items:center;justify-content:center;height:100vh}
form{background:#11193a;padding:24px;border-radius:12px;min-width:300px}
input{width:100%;margin:.5rem 0;padding:.6rem;border-radius:8px;border:1px solid #334}
button{width:100%;padding:.7rem;border:0;border-radius:8px;background:#6cf;color:#012;font-weight:700}
.msg{color:#faa;margin-bottom:.6rem}</style>
</head><body>
<form method="post" action="/login">
  <h2>🔐 Monitoring Login</h2>
  {msg}
  <input type="hidden" name="next" value="{next}">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">Login</button>
</form>
</body></html>"""

class BaseHandler(RequestHandler):
    def get_current_user(self):
        u = self.get_secure_cookie("session")
        return u.decode() if u else None

class Login(BaseHandler):
    def get(self):
        nxt = self.get_query_argument("next", "/")
        msg = self.get_query_argument("msg", "")
        self.write(HTML_LOGIN.format(msg=f'<div class="msg">{msg}</div>' if msg else "", next=nxt))

    def post(self):
        username = self.get_body_argument("username","").strip()
        password = self.get_body_argument("password","").strip()
        nxt = self.get_body_argument("next","/").strip() or "/"
        if USERS.get(username) == password:
            self.set_secure_cookie("session", username, httponly=True, samesite="lax")
            self.redirect(nxt)
        else:
            q = urllib.parse.urlencode({"next": nxt, "msg":"Invalid credentials"})
            self.redirect(f"/login?{q}")

class Logout(BaseHandler):
    def get(self):
        self.clear_cookie("session")
        self.redirect("/login")

class Health(RequestHandler):
    def get(self): self.write({"ok": True})

class Hello(BaseHandler):
    @authenticated
    def get(self): self.write({"hello": self.current_user})

def make_app():
    return Application([
        (r"/login", Login),
        (r"/logout", Logout),
        (r"/api/health", Health),  # open
        (r"/api/hello", Hello),    # protected
    ], cookie_secret=COOKIE_SECRET, login_url=LOGIN_URL, xsrf_cookies=False)

if __name__ == "__main__":
    app = make_app()
    app.listen(int(os.getenv("PORT","8080")), address="0.0.0.0")
    print("Tornado with login running on :8080")
    IOLoop.current().start()
PY

# ---- Streamlit (unchanged; hanya baca eve.json) ----
backup_if_exists streamlit/Dockerfile
cat > streamlit/Dockerfile <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir streamlit==1.37.1 pandas==2.2.2 watchdog==4.0.2
COPY app /app/app
EXPOSE 8501
DOCKER

backup_if_exists streamlit/app/app.py
cat > streamlit/app/app.py <<'PY'
import json, pandas as pd, streamlit as st
st.set_page_config(page_title="Monitoring", layout="wide")
st.title("🛰️ Streamlit Monitoring Dashboard")
st.write("GET /api/health -> harusnya {'ok': true}")
eve_path = "/var/log/suricata/eve.json"
rows=[]
try:
    with open(eve_path,'r') as f:
        for ln in f.readlines()[-200:]:
            try:
                d=json.loads(ln)
                rows.append({"ts":d.get("timestamp"),"src":d.get("src_ip"),
                             "dst":d.get("dest_ip"),
                             "sig": d.get("alert",{}).get("signature") if "alert" in d else None,
                             "proto":d.get("proto")})
            except: pass
except Exception as e:
    st.info(f"eve.json belum ada/akses gagal: {e}")
if rows:
    st.dataframe(pd.DataFrame(rows).tail(50), use_container_width=True)
st.caption("Akses via /monitor (redirect ke /login jika belum auth).")
PY

# ---- Frontend React minimal ----
backup_if_exists frontend/Dockerfile
cat > frontend/Dockerfile <<'DOCKER'
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
DOCKER

[ -f frontend/package.json ] || cat > frontend/package.json <<'JSON'
{
  "name": "monitoring-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": { "dev": "vite", "build": "vite build", "preview": "vite preview --host" },
  "dependencies": { "react": "^18.3.1", "react-dom": "^18.3.1" },
  "devDependencies": { "vite": "^5.3.4", "@vitejs/plugin-react": "^4.3.1" }
}
JSON

[ -f frontend/vite.config.js ] || cat > frontend/vite.config.js <<'JS'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins:[react()], build:{outDir:'dist'}, server:{host:true,port:5173} })
JS

[ -f frontend/index.html ] || cat > frontend/index.html <<'HTML'
<!doctype html><html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Monitoring</title></head>
<body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>
HTML

[ -f frontend/src/main.jsx ] || cat > frontend/src/main.jsx <<'JSX'
import React from "react"; import { createRoot } from "react-dom/client"
function App(){
  const [ok,setOk]=React.useState(null)
  React.useEffect(()=>{ fetch("/api/health").then(r=>r.json()).then(setOk).catch(()=>setOk({ok:false})) },[])
  return (<div style={{fontFamily:"sans-serif",padding:"2rem"}}>
    <h1>Monitoring Portal</h1>
    <p>API Health: <b>{ok?String(ok.ok):"loading..."}</b></p>
    <p><a href="/login">Login</a> → setelah login akses <a href="/monitor" target="_blank">/monitor</a></p>
  </div>)
}
createRoot(document.getElementById("root")).render(<App/>)
JSX

# ---- Suricata (no Hyperscan, x86-64-v2) target wlan0 ----
backup_if_exists suricata/Dockerfile.suricata
cat > suricata/Dockerfile.suricata <<'DOCKER'
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config curl ca-certificates \
    libyaml-dev libpcap-dev libnet1-dev libjansson-dev libcap-ng-dev \
    libmagic-dev libpcre2-dev libmaxminddb-dev libnfnetlink-dev \
    libnftnl-dev libnetfilter-queue-dev rustc cargo python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG SURI_VER=7.0.3
RUN curl -LO https://www.openinfosecfoundation.org/download/suricata-${SURI_VER}.tar.gz \
 && tar xzf suricata-${SURI_VER}.tar.gz \
 && cd suricata-${SURI_VER} \
 && CFLAGS="-O2 -pipe -march=x86-64-v2 -mtune=generic" \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
                --disable-hyperscan --disable-gccmarch-native \
 && make -j"$(nproc)" && make install-full && ldconfig \
 && cd / && rm -rf /build
RUN apt-get update && apt-get install -y --no-install-recommends ethtool jq && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN mkdir -p /var/log/suricata && mkdir -p /etc/suricata
ENTRYPOINT ["/entrypoint.sh"]
DOCKER

backup_if_exists suricata/entrypoint.sh
cat > suricata/entrypoint.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
IFACE="${SURI_IFACE:-wlan0}"

# Matikan GRO/LRO (wifi mungkin abaikan; tetap safe)
ethtool -K "$IFACE" gro off || true
ethtool -K "$IFACE" lro off || true

# Rules minimal
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update enable-source et/open abuse.ch/urlhaus || true
  for c in $(suricata-update list-categories | awk '{print $1}'); do
    case " $c " in
      *" scan "*|*" web-attack "*|*" web-php "*|*" sql "*|*" exploit "*|*" brute-force "*|*" dns "*|*" http "*|*" tls "*)
        suricata-update enable-category "$c" >/dev/null 2>&1 || true;;
      *)  suricata-update disable-category "$c" >/dev/null 2>&1 || true;;
    esac
  done
  suricata-update || true
fi

# Test & run
suricata -T -c /etc/suricata/suricata.yaml || { echo "[ERR] config invalid"; exit 1; }
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --runmode=autofp -D
BASH

backup_if_exists suricata/suricata.yaml
cat > suricata/suricata.yaml <<'YAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

af-packet:
  - interface: wlan0
    cluster-type: cluster_round_robin
    cluster-id: 99
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 200000
    buffer-size: 64512

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      community-id: yes
  - fast-log:
      enabled: yes
      filename: /var/log/suricata/fast.log
  - stats:
      enabled: yes
      filename: /var/log/suricata/stats.log

engine-analysis:
  rules-fast-pattern: yes

detect:
  profile: medium
  sgh-mpm-context: auto
  prefilter:
    default: mpm

threading:
  detect-thread-ratio: 0.75

stream: { inline: no }
unix-command: { enabled: yes }
logging: { default-log-level: info }
YAML

# ---- Copy kode lama kalau disediakan ----
copy_src(){
  local SRC="$1" DST="$2" WHAT="$3"
  if [ -n "$SRC" ] && [ -d "$SRC" ]; then
    say "Copy $WHAT dari $SRC -> $DST"
    rsync -a --delete --exclude='__pycache__' "$SRC"/ "$DST"/
  else
    warn "Sumber $WHAT tidak diberikan / tidak ada, pakai template default."
  fi
}
copy_src "$SOURCE_TORNADO"  "./backend/app"   "Tornado"
copy_src "$SOURCE_STREAMLIT" "./streamlit/app" "Streamlit"
copy_src "$SOURCE_FRONTEND"  "./frontend"      "Frontend"

say "DONE. Instruksi:"
echo "  1) (sekali saja) enable Docker at boot:  sudo systemctl enable --now docker"
echo "  2) Cloudflared login & create tunnel (sekali):"
echo "       docker run -it --rm --network host -v ./cloudflared:/home/nonroot/.cloudflared cloudflare/cloudflared:latest tunnel login"
echo "       docker run --rm -v ./cloudflared:/home/nonroot/.cloudflared cloudflare/cloudflared:latest tunnel create suri-tun"
echo "     -> ganti REPLACE_TUNNEL_ID di cloudflared/config.yml dengan Tunnel ID"
echo "  3) Build & run:   docker compose up -d --build"
echo "  4) Tes lokal:     curl -I http://localhost:8080/api/health"
echo "                    buka http://localhost:8080/login (user fox/bebek)"
echo "                    setelah login: http://localhost:8080/monitor"
#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-}"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$ROOT_DIR/docker-compose.yml"
CADDYDIR="$ROOT_DIR/caddy"

red(){ printf "\033[31m%s\033[0m\n" "$*"; }
grn(){ printf "\033[32m%s\033[0m\n" "$*"; }
ylw(){ printf "\033[33m%s\033[0m\n" "$*"; }
blu(){ printf "\033[34m%s\033[0m\n" "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { red "butuh '$1'"; exit 1; }; }

dig_q(){ dig +short "$@" 2>/dev/null || true; }

is_cf_ip() {
  local ip="$1"
  [[ "$ip" =~ ^104\.16\.|^104\.17\.|^104\.18\.|^104\.19\.|^104\.20\.|^104\.21\.|^104\.22\.|^104\.23\.|^104\.24\.|^104\.25\.|^104\.26\.|^172\.64\.|^172\.65\.|^172\.66\.|^172\.67\.|^188\.114\.|^2606:4700: ]] && return 0 || return 1
}

# 1) Pastikan stack up & landing public, /monitor protected
blu ">> Up stack & publish frontend…"
docker compose -f "$COMPOSE" up -d
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc 'npm run build >/dev/null 2>&1 || npm run build; rm -rf /webroot/* && cp -r dist/* /webroot/'

# Pastikan Caddyfile pakai basic_auth (bukan basicauth)
if grep -qE '\bbasicauth\b' "$CADDYDIR/Caddyfile"; then
  ylw ">> Ganti basicauth -> basic_auth"
  sed -i 's/\bbasicauth\b/basic_auth/g' "$CADDYDIR/Caddyfile"
fi

# Reload Caddy
blu ">> Reload Caddy…"
docker compose -f "$COMPOSE" exec -T caddy-rev caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null || true
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

# 2) Self test origin
blu ">> Self-test origin (localhost:8080)"
O1=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz || true)
O2=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ || true)
O3=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/monitor || true)
O4=$(curl -s -o /dev/null -u fox:foxziemalam999 -w '%{http_code}' -L http://127.0.0.1:8080/monitor -o /dev/null || true)
echo " /healthz : $O1  (harus 200)"
echo " /        : $O2  (harus 200)"
echo " /monitor : $O3  (harus 401)"
echo " /monitor(auth,-L) : $O4 (harus 200)"

if [[ "$O1$O2$O3" != "200200401" ]]; then
  red "Origin belum sesuai. Cek Caddyfile & restart Caddy container."
  docker compose -f "$COMPOSE" restart caddy-rev
  sleep 2
fi

# 3) Test dari cloudflared container ke origin
blu ">> Test dari dalam container cloudflared -> http://localhost:8080/healthz"
docker compose -f "$COMPOSE" exec -T cloudflared sh -lc 'apk add --no-cache curl >/dev/null 2>&1 || true; curl -sS -I http://localhost:8080/healthz || true' || true

# 4) Diagnosa Cloudflare (kalau domain diberikan)
if [[ -n "$DOMAIN" ]]; then
  blu ">> Diagnosa DNS/Cloudflare untuk: $DOMAIN"
  need dig || true

  ZONE="$(printf "%s\n" "$DOMAIN" | awk -F. '{n=NF; print $(n-1)"."$n}')"
  NS=$(dig_q NS "$ZONE")
  CNAME=$(dig_q CNAME "$DOMAIN")
  Arec=$(dig_q A "$DOMAIN")
  AAAArec=$(dig_q AAAA "$DOMAIN")

  echo " NS($ZONE):"
  echo "$NS" | sed 's/^/   - /'
  echo " CNAME($DOMAIN): ${CNAME:-<none>}"
  echo " A($DOMAIN):"
  echo "${Arec:-<none>}" | sed 's/^/   - /'
  echo " AAAA($DOMAIN):"
  echo "${AAAArec:-<none>}" | sed 's/^/   - /'

  # indikasi zone belum di Cloudflare
  if ! echo "$NS" | grep -qi 'cloudflare\.com'; then
    red ">> Nameserver zona tampaknya BUKAN Cloudflare."
    echo "   - Pindahkan nameserver domain ke Cloudflare (di registrar) agar DNS record public hostname dibuat/di-serve oleh Cloudflare."
  fi

  # cek apakah resolve ke Anycast CF
  CF_OK=0
  for ip in $Arec $AAAArec; do
    if is_cf_ip "$ip"; then CF_OK=1; fi
  done

  if [[ "$CF_OK" -eq 0 ]]; then
    red ">> $DOMAIN tidak mengarah ke edge Cloudflare."
    echo "   FIX:"
    echo "   1) Di Zero Trust > Access > Tunnels > (tunnel kamu) > Public hostnames:"
    echo "      - Hostname: $DOMAIN, Path: *, Service: http://localhost:8080"
    echo "   2) Pastikan di DNS Zone Cloudflare ada CNAME 'infra' (atau host yang dipakai) -> <UUID>.cfargotunnel.com (PROXIED/orange)."
    echo "   3) Tunggu propagasi DNS (1-5 menit), lalu tes lagi:"
    echo "      curl -I https://$DOMAIN/healthz"
    echo "      curl -I -L -u fox:foxziemalam999 https://$DOMAIN/monitor"
  else
    grn ">> $DOMAIN sudah resolve ke edge Cloudflare."
    echo "Tes HTTP via Cloudflare:"
    curl -s -o /dev/null -w "  /healthz : %{http_code}\n" "https://$DOMAIN/healthz" || true
    curl -s -o /dev/null -w "  /monitor(auth) : %{http_code}\n" -L -u fox:foxziemalam999 "https://$DOMAIN/monitor" || true
  fi
else
  ylw ">> Lewati tes Cloudflare (tidak ada domain arg). Contoh: sudo ./monitor_doctor.sh infra.dhimaslanangnugroho.my.id"
fi

grn ">> Done."
#!/usr/bin/env bash
set -euo pipefail

COMPOSE="cloudflared/docker-compose.yml"
SVC="streamlit-app"

say(){ printf ">> %s\n" "$*"; }

# --- Sumber kode Python yang akan di-copy ke container ---
read -r -d '' APP_PY <<"PY"
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")

from _live_tail_patch import render_live

# Jalankan tampilan live dari helper
render_live()
PY

read -r -d '' HELPER_PY <<"PY"
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

# ======================
# Konfigurasi & konstanta
# ======================
LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))     # baca N baris terakhir
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")   # penting untuk Caddy path prefix
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))  # minimal interval auto refresh

# ======================
# Util
# ======================
def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def _flatten_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Ambil kolom umum dan flatten alert/dns/flow seminimal mungkin."""
    out: Dict[str, Any] = {}
    out["timestamp"]   = raw.get("timestamp")
    out["event_type"]  = raw.get("event_type")
    out["src_ip"]      = raw.get("src_ip")
    out["src_port"]    = raw.get("src_port")
    out["dest_ip"]     = raw.get("dest_ip")
    out["dest_port"]   = raw.get("dest_port")
    out["proto"]       = raw.get("proto")
    out["app_proto"]   = raw.get("app_proto")

    a = raw.get("alert") or {}
    out["signature"]   = a.get("signature")
    out["sig_id"]      = a.get("signature_id")
    out["severity"]    = a.get("severity")

    dns = raw.get("dns") or {}
    out["dns_query"]   = dns.get("rrname") or dns.get("query")
    out["dns_rrtype"]  = dns.get("rrtype")
    out["dns_rcode"]   = dns.get("rcode")

    http = raw.get("http") or {}
    out["http_host"]   = http.get("hostname")
    out["http_url"]    = http.get("url")
    out["http_status"] = http.get("status")

    flow = raw.get("flow") or {}
    out["flow_to_srv"] = flow.get("bytes_toserver")
    out["flow_to_cli"] = flow.get("bytes_toclient")

    return out

def parse_eve_lines(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            # skip baris korup
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    # cast ringan
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame,
              event_type: str|None,
              sig_sub: str|None,
              src_sub: str|None,
              dst_sub: str|None,
              last_minutes: int|None) -> pd.DataFrame:
    out = df.copy()
    if event_type and event_type != "ALL":
        out = out[out["event_type"] == event_type]
    if sig_sub:
        out = out[out["signature"].fillna("").str.contains(sig_sub, case=False, na=False)]
    if src_sub:
        out = out[out["src_ip"].fillna("").str.contains(src_sub, case=False, na=False)]
    if dst_sub:
        out = out[out["dest_ip"].fillna("").str.contains(dst_sub, case=False, na=False)]
    if last_minutes and "timestamp" in out.columns and pd.api.types.is_datetime64_any_dtype(out["timestamp"]):
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=last_minutes)
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

# ======================
# UI utama
# ======================
def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    # Sidebar filters — beri key unik
    with st.sidebar:
        st.header("Filter")
        et = st.selectbox("Event Type", options=["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    # Tombol refresh dengan key unik agar tidak duplicate
    cols = st.columns([1,1,6])
    with cols[0]:
        if st.button("Refresh sekarang", key="btn_refresh_top"):
            st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    # Baca tail + parse
    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)

    # Terapkan filter
    dff = df_filter(df, et, sig, src, dst, win if win > 0 else None)

    # Ringkas atas
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    # Chart ringan
    if not dff.empty:
        cA, cB = st.columns(2)
        with cA:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with cB:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    # Data table
    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    # Downloads (subset saat ini)
    csv_io = io.StringIO()
    dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(), file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        # rebuild JSONL minimal dari kolom flatten
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(), file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    # Raw tail (beberapa baris terakhir)
    st.subheader("Tail (last 20 raw lines)")
    preview = "\n".join(lines[-20:])
    st.code(preview, language="json")

    # Auto refresh sederhana (tanpa lib eksternal)
    if auto:
        # Hindari loop ketat
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY
# --- END sources ---

if [[ ! -f "$COMPOSE" ]]; then
  echo "Compose file tidak ditemukan: $COMPOSE" >&2
  exit 1
fi

echo ">> Pastikan container $SVC up..."
docker compose -f "$COMPOSE" up -d "$SVC" >/dev/null

CID=$(docker compose -f "$COMPOSE" ps -q "$SVC")
if [[ -z "$CID" ]]; then
  echo "Container $SVC tidak ditemukan" >&2
  exit 2
fi

echo ">> Deploy app.py & helper ke container..."
docker exec -i "$CID" sh -lc 'mkdir -p /app/app'
printf "%s" "$APP_PY"   | docker exec -i "$CID" sh -lc 'cat > /app/app/app.py'
printf "%s" "$HELPER_PY"| docker exec -i "$CID" sh -lc 'cat > /app/app/_live_tail_patch.py'

echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC" >/dev/null

echo ">> Quick log (tail 40):"
docker compose -f "$COMPOSE" logs -n 40 "$SVC" || true

echo ">> Cek cepat (origin via Caddy):"
curl -sI http://127.0.0.1:8080/monitor | head -n1 || true
echo "Selesai ✓"
#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(pwd)}"
COMPOSE="${COMPOSE:-$ROOT/docker-compose.yml}"
SVC="streamlit-app"

echo ">> Ensure $SVC up..."
docker compose -f "$COMPOSE" up -d "$SVC" >/dev/null

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Helper baru: semua widget pakai key v2 (unik)
cat > "$TMP/_live_tail_patch.py" <<'PY'
import os, time, json
import streamlit as st
from typing import List, Tuple

def _tail_lines(path: str, max_lines: int = 200) -> Tuple[float | None, List[str]]:
    if not os.path.exists(path):
        return None, []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= max_lines:
                step = block if size - block > 0 else size
                size -= step
                f.seek(size)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="ignore")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return os.path.getmtime(path), lines[-max_lines:]
    except Exception as e:
        return None, [f"# tail error: {e}"]

def _safe_rows(lines: List[str]) -> tuple[list[dict], int, int]:
    ok, bad = 0, 0
    rows: list[dict] = []
    for ln in lines:
        try:
            rows.append(json.loads(ln)); ok += 1
        except Exception:
            bad += 1
    return rows, ok, bad

def render_live(path: str = "/var/log/suricata/eve.json", limit: int = 200):
    st.subheader("Live Tail: eve.json")
    st.caption(f"Path: {path}")

    c1, c2, c3 = st.columns([1,1,2])
    with c1:
        limit_val = st.number_input("Baris terakhir", min_value=50, max_value=5000,
                                    value=int(limit), step=50, key="live_limit_inp_v2")
    with c2:
        auto = st.toggle("Auto refresh", value=True, key="live_auto_tgl_v2")
    with c3:
        if st.button("Refresh sekarang", key="live_refresh_btn_v2"):
            st.rerun()

    mtime, lines = _tail_lines(path, max_lines=int(limit_val))
    if lines is None or (mtime is None and not lines):
        st.info(f"File belum ada: {path}")
        return

    rows, ok, bad = _safe_rows(lines)
    st.caption(f"Parsed OK: {ok} • Error: {bad} • Total tail: {len(lines)}")

    st.code("\n".join(lines)[-120_000:], language="json")

    if auto:
        time.sleep(2)
        st.rerun()
PY

echo ">> Push helper v2 ke container..."
docker compose -f "$COMPOSE" cp "$TMP/_live_tail_patch.py" "$SVC":/app/app/_live_tail_patch.py >/dev/null

# Patch app.py: tambahkan key pada tombol "Refresh sekarang" yang belum punya key
cat > "$TMP/patch_app_buttons.py" <<'PY'
import re, sys, io
APP="/app/app/app.py"
src = io.open(APP, "r", encoding="utf-8", errors="ignore").read()

# case 1: st.button("Refresh sekarang")
src = re.sub(
    r'st\.button\(\s*([\'"])Refresh sekarang\1\s*\)',
    r'st.button("\g<1>Refresh sekarang\g<1>", key="app_refresh_btn_v2")',
    src
)

# case 2: st.button("Refresh sekarang", ... ) tapi belum ada key=
def inject_key(m):
    labelq = m.group(1)
    rest = m.group(2)
    if "key=" in rest:
        return m.group(0)
    rest = rest.lstrip()
    if rest.startswith(")"):
        return f'st.button({labelq}Refresh sekarang{labelq}, key="app_refresh_btn_v2")'
    return f'st.button({labelq}Refresh sekarang{labelq}, key="app_refresh_btn_v2", {rest}'
src = re.sub(
    r'st\.button\(\s*([\'"])Refresh sekarang\1\s*,\s*([^)]+)\)',
    inject_key,
    src
)

io.open(APP, "w", encoding="utf-8").write(src)
print("OK: app.py button keys patched (if any).")
PY

echo ">> Patch app.py (button keys)..."
docker compose -f "$COMPOSE" exec -T "$SVC" python /tmp/patch_app_buttons.py

echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC" >/dev/null

echo ">> Preview helper (1..60):"
docker compose -f "$COMPOSE" exec -T "$SVC" sh -lc 'nl -ba /app/app/_live_tail_patch.py | sed -n "1,60p"'

echo ">> Grep tombol di app.py:"
docker compose -f "$COMPOSE" exec -T "$SVC" sh -lc 'grep -n "st.button(.*Refresh sekarang" -n /app/app/app.py || true'

echo ">> Tail 80 log:"
docker compose -f "$COMPOSE" logs -n 80 "$SVC" | tail -n 80

echo ">> Quick check:"
echo "   curl -I http://127.0.0.1:8080/monitor                # 401"
echo "   curl -I -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor   # 200"
#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(pwd)}"
COMPOSE="${COMPOSE:-$ROOT/docker-compose.yml}"
SVC="streamlit-app"

echo ">> Ensure container ${SVC} up..."
docker compose -f "$COMPOSE" up -d "$SVC" >/dev/null

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---- Python patcher with full detection & fixes ----
cat > "$TMP/patch_and_report.py" <<'PY'
import os, re, json, textwrap, sys

APP = "/app/app/app.py"
HELP = "/app/app/_live_tail_patch.py"

def rd(p):
    with open(p,"r",encoding="utf-8",errors="ignore") as f: return f.read()
def wr(p,s):
    with open(p,"w",encoding="utf-8") as f: f.write(s)

def slug(s):
    s = re.sub(r"[^a-zA-Z0-9]+","_", s).strip("_").lower()
    return s or "x"

report = {"app_py_exists": os.path.exists(APP), "helper_exists": os.path.exists(HELP)}

if not os.path.exists(APP):
    print(json.dumps({"error":"app.py not found","report":report}, indent=2))
    sys.exit(1)

src = rd(APP)

# ---- DETECT ----
report["set_page_config_count"] = len(re.findall(r"\bst\.set_page_config\s*\(", src))
report["has_experimental_rerun"] = bool(re.search(r"\bst\.experimental_rerun\b", src))
report["imports_app_dot_helper"] = bool(re.search(r"from\s+app\._live_tail_patch\s+import|import\s+app\._live_tail_patch\s+as", src))
report["imports_local_helper"]  = bool(re.search(r"from\s+_live_tail_patch\s+import|import\s+_live_tail_patch\s+as", src))

# collect button calls without key (approximate)
btn_labels = re.findall(r"st\.button\(\s*([\"'])(.+?)\1\s*(?:,|\))", src)
report["buttons_in_app"] = [lbl for _,lbl in btn_labels]

# ---- FIXES on app.py ----

# 1) remove all set_page_config anywhere
src = re.sub(r"(?m)^\s*st\.set_page_config\([^)]*\)\s*$", "", src)

# 2) ensure we import streamlit and set_page_config at top
lines = src.splitlines()
ins = 0
if lines and lines[0].startswith("#!"):
    ins = 1
if ins < len(lines) and re.match(r"#.*coding[:=]\s*utf-?8", lines[ins] if ins < len(lines) else ""):
    ins += 1

# remove any existing "import streamlit as st" to avoid duplicates
lines = [ln for ln in lines if not re.match(r"^\s*import\s+streamlit\s+as\s+st\s*$", ln)]

header = [
    "import streamlit as st",
    'st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")',
    "",
]
src = "\n".join(lines[:ins] + header + lines[ins:])

# 3) replace experimental_rerun with rerun()
src = re.sub(r"\bst\.experimental_rerun\b", "st.rerun()", src)

# 4) force helper import to LOCAL
src = re.sub(r"(?m)^\s*from\s+app\._live_tail_patch\s+import\s+", "from _live_tail_patch import ", src)
src = re.sub(r"(?m)^\s*import\s+app\._live_tail_patch\s+as\s+", "import _live_tail_patch as ", src)

# 5) OPTIONAL: auto-key buttons IN APP if no key (safe, deterministic)
def add_key_to_buttons(code):
    def repl(m):
        quote, label = m.group(1), m.group(2)
        rest = m.group(3) or ""
        # jika sudah ada 'key=' di rest, biarkan
        if "key=" in rest:
            return m.group(0)
        key = f'key="btn_{slug(label)}"'
        if rest.strip():
            return f'st.button({quote}{label}{quote}, {key}{rest})'
        else:
            return f'st.button({quote}{label}{quote}, {key})'
    # hanya untuk pola satu baris yang umum
    pat = re.compile(r'st\.button\(\s*([\'"])(.+?)\1\s*(,(?![^(]*\)))?')
    return pat.sub(repl, code)

src = add_key_to_buttons(src)

# write back app.py
wr(APP, src)

# ---- Write robust helper (NO set_page_config, unique keys, resilient parser) ----
helper = textwrap.dedent('''
    import os, time, json
    import streamlit as st
    from typing import List, Tuple

    def _tail_lines(path: str, max_lines: int = 200) -> Tuple[float | None, List[str]]:
        if not os.path.exists(path):
            return None, []
        try:
            # Efficient tail
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                block = 8192
                data = b""
                while size > 0 and data.count(b"\\n") <= max_lines:
                    step = block if size - block > 0 else size
                    size -= step
                    f.seek(size)
                    data = f.read(step) + data
            text = data.decode("utf-8", errors="ignore")
            lines = [ln for ln in text.splitlines() if ln.strip()]
            return os.path.getmtime(path), lines[-max_lines:]
        except Exception as e:
            return None, [f"# tail error: {e}"]

    def _safe_rows(lines: List[str]) -> tuple[list[dict], int, int]:
        ok, bad = 0, 0
        rows: list[dict] = []
        for ln in lines:
            try:
                obj = json.loads(ln)
                rows.append(obj); ok += 1
            except Exception:
                bad += 1
        return rows, ok, bad

    def render_live(path: str = "/var/log/suricata/eve.json", limit: int = 200):
        st.subheader("Live Tail: eve.json")
        st.caption(f"Path: {path}")

        c1, c2, c3 = st.columns([1,1,2])
        with c1:
            limit_val = st.number_input("Baris terakhir", min_value=50, max_value=5000, value=int(limit), step=50, key="live_limit_inp")
        with c2:
            auto = st.toggle("Auto refresh", value=True, key="live_auto_tgl")
        with c3:
            if st.button("Refresh sekarang", key="live_refresh_btn"):
                st.rerun()

        mtime, lines = _tail_lines(path, max_lines=int(limit_val))
        if lines is None or (mtime is None and not lines):
            st.info(f"File belum ada: {path}")
            return

        rows, ok, bad = _safe_rows(lines)
        st.caption(f"Parsed OK: {ok} • Error: {bad} • Total tail: {len(lines)}")

        # tampilkan raw tail sebagai JSONL
        st.code("\\n".join(lines)[-120_000:], language="json")

        if auto:
            time.sleep(2)
            st.rerun()
''').lstrip()

with open(HELP, "w", encoding="utf-8") as f:
    f.write(helper)

# sanity checks
rep_after = rd(APP)
report["final_set_page_config_count"] = len(re.findall(r"\bst\.set_page_config\s*\(", rep_after))
report["final_has_experimental_rerun"] = bool(re.search(r"\bst\.experimental_rerun\b", rep_after))
report["helper_has_page_config"] = "set_page_config(" in rd(HELP)

print(json.dumps({"status":"patched","report":report}, indent=2))
PY

echo ">> Push patcher ke container..."
docker compose -f "$COMPOSE" cp "$TMP/patch_and_report.py" "$SVC":/tmp/patch_and_report.py >/dev/null

echo ">> Jalankan patcher & report..."
docker compose -f "$COMPOSE" exec -T "$SVC" python /tmp/patch_and_report.py

echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC" >/dev/null

echo ">> Grep ringkas (validasi):"
docker compose -f "$COMPOSE" exec -T "$SVC" sh -lc 'echo "app.py:"; nl -ba /app/app/app.py | sed -n "1,30p"; echo; echo "-- set_page_config occurrences --"; grep -n "set_page_config" /app/app/app.py || true; echo; echo "helper check:"; grep -n "set_page_config" /app/app/_live_tail_patch.py || echo "(OK: no set_page_config)"'

echo ">> Tail 80 log streamlit-app:"
docker compose -f "$COMPOSE" logs -n 80 "$SVC" | tail -n 80

echo ">> Quick check (origin via Caddy):"
echo "   curl -I http://127.0.0.1:8080/monitor                 # 401"
echo "   curl -I -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor   # 200"
#!/usr/bin/env bash
set -Eeuo pipefail

# Jalankan dari folder: /home/whoami/Documents/server/9aug2025/cloudflared
COMPOSE="docker-compose.yml"
SVC_ST="streamlit-app"
SVC_SURI="suricata"

say(){ printf ">> %s\n" "$*"; }
cid(){ docker compose -f "$COMPOSE" ps -q "$1" 2>/dev/null || true; }
up(){ docker compose -f "$COMPOSE" up -d "$@" >/dev/null; }

# ===== Kredensial login internal (selaras demo) =====
read -r -d '' APP_PY <<"PY"
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")

from typing import Dict
from _live_tail_patch import render_live

CREDENTIALS: Dict[str, str] = {
    "fox": "foxziemalam999",
    "adit": "aditidn123",
    "bebek": "bebekcantik123",
}

def require_login() -> bool:
    if st.session_state.get("logged_in") and st.session_state.get("user"):
        return True
    st.title("Masuk • Suricata Monitor")
    st.caption("Proteksi internal tambahan (di luar Basic Auth Caddy).")
    with st.form("login_form", clear_on_submit=False, border=True):
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        ok = st.form_submit_button("Masuk", use_container_width=True)
    if ok:
        if u in CREDENTIALS and CREDENTIALS[u] == p:
            st.session_state["logged_in"] = True
            st.session_state["user"] = u
            st.toast(f"Selamat datang, {u}!", icon="✅")
            st.rerun()
        else:
            st.error("Username/password salah.", icon="⚠️")
    return False

def logout_button():
    with st.sidebar:
        if st.session_state.get("logged_in"):
            if st.button("Keluar", key="btn_logout_sidebar"):
                for k in ("logged_in","user"): st.session_state.pop(k, None)
                st.rerun()

def main():
    if not require_login(): return
    logout_button()
    render_live()

if __name__ == "__main__":
    main()
PY

# ===== Helper: parser + UI (tombol/keys unik; no set_page_config di sini) =====
read -r -d '' HELPER_PY <<"PY"
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))

def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def _flatten_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["timestamp"]   = raw.get("timestamp")
    out["event_type"]  = raw.get("event_type")
    out["src_ip"]      = raw.get("src_ip")
    out["src_port"]    = raw.get("src_port")
    out["dest_ip"]     = raw.get("dest_ip")
    out["dest_port"]   = raw.get("dest_port")
    out["proto"]       = raw.get("proto")
    out["app_proto"]   = raw.get("app_proto")
    a = raw.get("alert") or {}
    out["signature"]   = a.get("signature")
    out["sig_id"]      = a.get("signature_id")
    out["severity"]    = a.get("severity")
    dns = raw.get("dns") or {}
    out["dns_query"]   = dns.get("rrname") or dns.get("query")
    out["dns_rrtype"]  = dns.get("rrtype")
    out["dns_rcode"]   = dns.get("rcode")
    http = raw.get("http") or {}
    out["http_host"]   = http.get("hostname")
    out["http_url"]    = http.get("url")
    out["http_status"] = http.get("status")
    flow = raw.get("flow") or {}
    out["flow_to_srv"] = flow.get("bytes_toserver")
    out["flow_to_cli"] = flow.get("bytes_toclient")
    return out

def parse_eve_lines(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln: continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame, event_type, sig_sub, src_sub, dst_sub, last_minutes):
    out = df.copy()
    if event_type and event_type != "ALL":
        out = out[out["event_type"] == event_type]
    if sig_sub:
        out = out[out["signature"].fillna("").str.contains(sig_sub, case=False, na=False)]
    if src_sub:
        out = out[out["src_ip"].fillna("").str.contains(src_sub, case=False, na=False)]
    if dst_sub:
        out = out[out["dest_ip"].fillna("").str.contains(dst_sub, case=False, na=False)]
    if last_minutes and "timestamp" in out.columns and pd.api.types.is_datetime64_any_dtype(out["timestamp"]):
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(last_minutes))
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    with st.sidebar:
        st.header("Filter")
        et  = st.selectbox("Event Type", ["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    if st.button("Refresh sekarang", key="btn_refresh_top"):
        st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)
    dff = df_filter(df, et, sig, src, dst, win if win and int(win) > 0 else None)

    c1,c2,c3,c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    if not dff.empty:
        a,b = st.columns(2)
        with a:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with b:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    csv_io = io.StringIO(); dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(),
                       file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(),
                       file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    st.subheader("Tail (last 20 raw lines)")
    st.code("\n".join(lines[-20:]), language="json")

    if auto:
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY

seed_suricata(){
  say "Periksa Suricata & seed eve.json bila kosong..."
  up "$SVC_SURI"
  local CS; CS="$(cid "$SVC_SURI")"; [[ -n "$CS" ]] || return 0
  docker compose -f "$COMPOSE" exec -T "$SVC_SURI" sh -lc '
    p=/var/log/suricata/eve.json;
    mkdir -p /var/log/suricata;
    if [ ! -s "$p" ]; then
      TS=$(date -u +%Y-%m-%dT%H:%M:%SZ);
      : > "$p";
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.10\",\"dest_ip\":\"10.0.0.5\",\"alert\":{\"signature\":\"DEMO Seed 1\",\"severity\":2}}" >> "$p";
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"dns\",\"src_ip\":\"192.168.1.11\",\"dest_ip\":\"1.1.1.1\",\"dns\":{\"query\":\"example.com\",\"rrtype\":\"A\",\"rcode\":\"NOERROR\"}}" >> "$p";
      echo "{\"timestamp\":\"$TS\",\"event_type\":\"flow\",\"src_ip\":\"192.168.1.12\",\"dest_ip\":\"10.0.0.8\",\"flow\":{\"bytes_toserver\":1234,\"bytes_toclient\":4321}}" >> "$p";
      chmod 666 "$p";
    fi'
}

deploy_streamlit(){
  say "Deploy ulang kode ke container Streamlit..."
  up "$SVC_ST"
  local CID; CID="$(cid "$SVC_ST")"; [[ -n "$CID" ]] || { echo "!! container $SVC_ST tidak ada"; exit 2; }
  docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'rm -rf /app/app && mkdir -p /app/app'
  printf "%s" "$APP_PY"    | docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'cat > /app/app/app.py'
  printf "%s" "$HELPER_PY" | docker compose -f "$COMPOSE" exec -T "$SVC_ST" sh -lc 'cat > /app/app/_live_tail_patch.py'
  docker compose -f "$COMPOSE" restart "$SVC_ST" >/dev/null
}

self_test(){
  say "Self-test origin (Caddy → 127.0.0.1:8080)"
  curl -sI http://127.0.0.1:8080/healthz | head -n1 || true
  curl -sI http://127.0.0.1:8080/        | head -n1 || true
  curl -sI http://127.0.0.1:8080/monitor | head -n1 || true
  say "Tail 60 log streamlit:"
  docker compose -f "$COMPOSE" logs -n 60 "$SVC_ST" || true
}

say "Up stack minimal..."
up "$SVC_ST" "$SVC_SURI"
seed_suricata
deploy_streamlit
self_test
say "Done ✓ — akses /monitor (Basic Auth Caddy → login Streamlit internal: fox/foxziemalam999, adit/aditidn123, bebek/bebekcantik123)"
#!/usr/bin/env bash
# streamlit_force_fix_and_logs.sh
set -euo pipefail
BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"
APP_HOST="${APP_HOST:-$BASE/streamlit/app/app.py}"
APP_CONT="/app/app/app.py"
SVC="streamlit-app"

echo ">> Compose: $COMPOSE"
[ -f "$COMPOSE" ] || { echo "ERR: compose tidak ditemukan"; exit 1; }

# 1) Pastikan service up
docker compose -f "$COMPOSE" up -d $SVC >/dev/null

CID="$(docker compose -f "$COMPOSE" ps -q $SVC)"
[ -n "$CID" ] || { echo "ERR: container $SVC belum jalan"; exit 1; }

# 2) Tampilkan baris yang mengandung 'rerun' di host & container
echo ">> Cek host app.py (jika ada):"
if [ -f "$APP_HOST" ]; then
  grep -nE 'experimental_rerun|st\.rerun' "$APP_HOST" || echo "(tidak ketemu 'rerun' di host)"
else
  echo "(file host tidak ada: $APP_HOST)"
fi

echo ">> Cek container app.py:"
docker compose -f "$COMPOSE" exec -T $SVC sh -lc "grep -nE 'experimental_rerun|st\.rerun' $APP_CONT || true"

# 3) Jika masih ada 'experimental_rerun' di container → paksa timpa dari host
if docker compose -f "$COMPOSE" exec -T $SVC sh -lc "grep -q 'experimental_rerun' $APP_CONT"; then
  echo ">> Masih ada experimental_rerun di container → force copy dari host..."
  [ -f "$APP_HOST" ] || { echo "ERR: file host $APP_HOST tidak ada untuk dicopy"; exit 1; }
  docker cp "$APP_HOST" "$CID:$APP_CONT"
  docker compose -f "$COMPOSE" restart $SVC >/dev/null
else
  echo ">> OK: container sudah pakai st.rerun()"
fi

# 4) Tes cepat health streamlit via Caddy (origin)
echo ">> Tes HTTP origin (via Caddy di 127.0.0.1:8080):"
curl -sI http://127.0.0.1:8080/monitor | head -n 1 || true

# 5) Tail log streamlit
echo ">> Logs streamlit-app (tail 200):"
docker compose -f "$COMPOSE" logs -n 200 $SVC
#!/usr/bin/env bash
set -euo pipefail

# === Lokasi compose ===
ROOT="${ROOT:-$(pwd)}"
COMPOSE="${COMPOSE:-$ROOT/docker-compose.yml}"

echo ">> Ensure container streamlit-app up..."
docker compose -f "$COMPOSE" up -d streamlit-app >/dev/null

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------- Python patcher di dalam container ----------------
cat > "$TMP/patch.py" <<'PY'
import os, re, io, sys

APP = "/app/app/app.py"
HELP = "/app/app/_live_tail_patch.py"

def rd(p):
    with open(p,"r",encoding="utf-8",errors="ignore") as f:
        return f.read()
def wr(p,s):
    with open(p,"w",encoding="utf-8") as f:
        f.write(s)

# Backup sekali
if not os.path.exists(APP + ".bak"):
    try:
        with open(APP + ".bak","x",encoding="utf-8") as f: f.write(rd(APP))
    except: pass

src = rd(APP)

# --- 1) Buang SEMUA set_page_config yang tersebar ---
src = re.sub(r"(?m)^\s*st\.set_page_config\([^)]*\)\s*$", "", src)

# --- 2) Ganti experimental_rerun -> rerun() ---
src = re.sub(r"\bst\.experimental_rerun\b", "st.rerun()", src)

# --- 3) Perbaiki import helper menjadi lokal ---
# from app._live_tail_patch import X -> from _live_tail_patch import X
src = re.sub(r"(?m)^\s*from\s+app\._live_tail_patch\s+import\s+", "from _live_tail_patch import ", src)
# import app._live_tail_patch as Y -> import _live_tail_patch as Y
src = re.sub(r"(?m)^\s*import\s+app\._live_tail_patch\s+as\s+", "import _live_tail_patch as ", src)

# --- 4) Pastikan import streamlit + set_page_config di paling awal ---
lines = src.splitlines()

ins = 0
if lines and lines[0].startswith("#!"):
    ins = 1
if ins < len(lines) and re.match(r"#.*coding[:=]\s*utf-?8", lines[ins] if ins < len(lines) else ""):
    ins += 1

# Hilangkan import streamlit lama biar gak dobel
lines = [ln for ln in lines if not re.match(r"^\s*import\s+streamlit\s+as\s+st\s*$", ln)]

header = [
    "import streamlit as st",
    'st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")',
    "",
]
src = "\n".join(lines[:ins] + header + lines[ins:])

wr(APP, src)

# --- 5) Tulis ulang helper TANPA set_page_config ---
helper = r'''import os, time, json
import streamlit as st

def _tail_lines(path, max_lines=200):
    if not os.path.exists(path):
        return None, []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= max_lines:
                step = chunk if size - chunk > 0 else size
                size -= step
                f.seek(size)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="ignore")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return os.path.getmtime(path), lines[-max_lines:]
    except Exception as e:
        return None, [f"# tail error: {e}"]

def render_live(path="/var/log/suricata/eve.json", limit=200):
    st.subheader("Live Tail: eve.json")
    st.caption(f"Path: {path}")

    col1, col2, col3 = st.columns([1,1,2])
    with col1:
        limit = int(st.number_input("Baris terakhir", min_value=50, max_value=5000, value=int(limit), step=50))
    with col2:
        auto = st.toggle("Auto refresh", value=True)
    with col3:
        if st.button("Refresh sekarang"):
            st.rerun()

    mt, lines = _tail_lines(path, max_lines=limit)
    if lines is None:
        st.info(f"File belum ada: {path}")
        return

    preview = "\n".join(lines)[-120_000:]
    st.code(preview, language="json")

    if auto:
        time.sleep(2)
        st.rerun()
'''
with open(HELP,"w",encoding="utf-8") as f:
    f.write(helper)

# sanity: pastikan helper tak mengandung set_page_config
if "set_page_config" in rd(HELP):
    print("Helper masih memanggil set_page_config! Gagal.", file=sys.stderr)
    sys.exit(2)

print("OK: Patched app.py & helper")
PY

# ---------------- Copy & execute patch ----------------
echo ">> Push patcher ke container..."
docker compose -f "$COMPOSE" cp "$TMP/patch.py" streamlit-app:/tmp/patch.py >/dev/null

echo ">> Jalankan patcher..."
docker compose -f "$COMPOSE" exec -T streamlit-app python /tmp/patch.py

echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart streamlit-app >/dev/null

# ---------------- Bukti & log ----------------
echo ">> Preview app.py (baris 1..30):"
docker compose -f "$COMPOSE" exec -T streamlit-app sh -lc 'nl -ba /app/app/app.py | sed -n "1,30p"'

echo ">> Cari set_page_config di app.py & helper:"
docker compose -f "$COMPOSE" exec -T streamlit-app sh -lc 'grep -n "set_page_config" -n /app/app/app.py || true'
docker compose -f "$COMPOSE" exec -T streamlit-app sh -lc 'grep -n "set_page_config" -n /app/app/_live_tail_patch.py || true'

echo ">> Tail log streamlit (80 baris):"
docker compose -f "$COMPOSE" logs -n 80 streamlit-app | tail -n 80

echo ">> Quick check:"
echo "   curl -I http://127.0.0.1:8080/monitor             # 401"
echo "   curl -I -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor   # 200"
#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(pwd)}"
COMPOSE="${COMPOSE:-$ROOT/docker-compose.yml}"

echo ">> Ensure streamlit container up..."
docker compose -f "$COMPOSE" up -d streamlit-app >/dev/null

TMP="/tmp/st_fix_$$"
mkdir -p "$TMP"

# ---------- Python patcher: pastikan set_page_config 1x di paling awal,
# fix import helper, dan ganti experimental_rerun -> rerun() ----------
cat > "$TMP/patch.py" <<'PY'
import os, re, io

APP="/app/app/app.py"

def read(p): 
    return open(p,"r",encoding="utf-8",errors="ignore").read()
def write(p,s):
    open(p,"w",encoding="utf-8").write(s)

src = read(APP)

# 0) Buat backup sekali
bk = APP + ".bak"
if not os.path.exists(bk):
    try: open(bk,"x").write(src)
    except: pass

# 1) Hapus SEMUA set_page_config()
src = re.sub(r"(?m)^\s*st\.set_page_config\([^)]*\)\s*$","",src)

# 2) Ganti experimental_rerun -> rerun()
src = re.sub(r"\bst\.experimental_rerun\b","st.rerun()",src)

# 3) Perbaiki import helper "from app._live_tail_patch import ..." -> lokal
src = re.sub(r"\bfrom\s+app\._live_tail_patch\s+import\s+","from _live_tail_patch import ",src)

# 4) Pastikan "import streamlit as st" dan jadikan header + set_page_config di PALING AWAL
lines = src.splitlines()

# Cari shebang/encoding di awal untuk tempat sisip
ins = 0
if lines and lines[0].startswith("#!"):
    ins = 1
if len(lines) > ins and re.match(r"#.*coding[:=]\s*utf-?8", lines[ins] if ins < len(lines) else ""):
    ins += 1

# buang semua import streamlit lama
lines = [ln for ln in lines if not re.match(r"^\s*import\s+streamlit\s+as\s+st\s*$", ln)]

header = [
    "import streamlit as st",
    'st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")',
]

# sisipkan header di posisi ins
src = "\n".join(lines[:ins] + header + [""] + lines[ins:])

write(APP, src)
print("Patched:", APP)
PY

# ---------- Helper live tail: TIDAK memanggil set_page_config ----------
cat > "$TMP/_live_tail_patch.py" <<'PY2'
import os, time, json
import streamlit as st

def _tail_lines(path, max_lines=200):
    if not os.path.exists(path):
        return None, []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= max_lines:
                step = chunk if size - chunk > 0 else size
                size -= step
                f.seek(size)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="ignore")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return os.path.getmtime(path), lines[-max_lines:]
    except Exception as e:
        return None, [f"# tail error: {e}"]

def render_live(path="/var/log/suricata/eve.json", limit=200):
    st.subheader("Live Tail: eve.json")
    st.caption(f"Path: {path}")

    c1, c2, c3 = st.columns([1,1,2])
    with c1:
        limit = st.number_input("Baris terakhir", min_value=50, max_value=5000, value=int(limit), step=50)
    with c2:
        auto = st.toggle("Auto refresh", value=True)
    with c3:
        if st.button("Refresh sekarang"):
            st.rerun()

    mt, lines = _tail_lines(path, max_lines=int(limit))
    if lines is None:
        st.info(f"File belum ada: {path}")
        return

    preview = "\n".join(lines)[-120_000:]
    st.code(preview, language="json")

    if auto:
        time.sleep(2)
        st.rerun()
PY2

# ---------- Copy ke container ----------
echo ">> Copy patch & helper ke container..."
docker compose -f "$COMPOSE" cp "$TMP/patch.py" streamlit-app:/tmp/patch.py >/dev/null
docker compose -f "$COMPOSE" cp "$TMP/_live_tail_patch.py" streamlit-app:/app/app/_live_tail_patch.py >/dev/null

# ---------- Jalankan patch ----------
echo ">> Jalankan patch..."
docker compose -f "$COMPOSE" exec -T streamlit-app python /tmp/patch.py

# ---------- Restart streamlit ----------
echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart streamlit-app >/dev/null

# ---------- Tampilkan log ringkas ----------
echo ">> Tail 80 log streamlit-app:"
docker compose -f "$COMPOSE" logs -n 80 streamlit-app | tail -n 80

# ---------- Tes cepat via Caddy Origin ----------
echo ">> Quick-check:"
echo "   curl -I http://127.0.0.1:8080/monitor              # 401"
echo "   curl -I -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor   # 200"
BASH
