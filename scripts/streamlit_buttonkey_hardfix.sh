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
