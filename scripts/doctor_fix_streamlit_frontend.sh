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
