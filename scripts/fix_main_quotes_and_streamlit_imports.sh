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
