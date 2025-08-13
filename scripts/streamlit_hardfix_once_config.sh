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
