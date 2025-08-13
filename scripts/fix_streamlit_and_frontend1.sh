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

