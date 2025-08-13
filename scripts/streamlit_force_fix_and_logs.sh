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
