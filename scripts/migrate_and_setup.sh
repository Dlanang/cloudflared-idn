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
