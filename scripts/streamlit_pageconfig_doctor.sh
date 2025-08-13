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
