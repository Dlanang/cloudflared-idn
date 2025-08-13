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
