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
