#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$ROOT/docker-compose.yml"
STREAMLIT_APP="$ROOT/streamlit/app/app.py"
CADDYFILE="$ROOT/caddy/Caddyfile"
WEBROOT_VOL="monitoring_stack_webroot"

say()  { printf "\033[34m%s\033[0m\n" ">> $*"; }
ok()   { printf "\033[32m%s\033[0m\n" "✔ $*"; }
warn() { printf "\033[33m%s\033[0m\n" "WARN: $*"; }

# --- 1) Patch Streamlit app (perbaiki st.experimental_rerun + fitur log+download) ---
say "Patch Streamlit app..."
mkdir -p "$(dirname "$STREAMLIT_APP")"
cp -a "$STREAMLIT_APP" "$STREAMLIT_APP.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
cat > "$STREAMLIT_APP" <<'PY'
import os, json, time
from collections import deque
from typing import Deque, Dict, Any, List
import pandas as pd
import streamlit as st

# ====== Konfigurasi ======
LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
MAX_TAIL = int(os.getenv("EVE_MAX_LINES", "10000"))  # ambil N baris terakhir
PAGE_TITLE = "Suricata Monitoring"
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")

st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon="🛡️",
    layout="wide",
    menu_items={"About": "Monitoring Suricata – tugas akhir ID-NETWORKERS"}
)

# ====== Util ======
def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def parse_eve(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        try:
            obj = json.loads(ln)
            # flatten beberapa field umum
            flat = {
                "timestamp": obj.get("timestamp") or obj.get("@timestamp"),
                "event_type": obj.get("event_type"),
                "src_ip": obj.get("src_ip"),
                "src_port": obj.get("src_port"),
                "dest_ip": obj.get("dest_ip"),
                "dest_port": obj.get("dest_port"),
                "proto": obj.get("proto"),
                "alert_severity": (obj.get("alert") or {}).get("severity"),
                "alert_signature": (obj.get("alert") or {}).get("signature"),
            }
            rows.append({**flat, **obj})
        except Exception:
            # skip baris rusak
            continue
    if not rows:
        return pd.DataFrame()
    df = pd.json_normalize(rows, max_level=1)
    if "timestamp" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        except Exception:
            pass
    return df

@st.cache_data(ttl=5)
def load_df(max_tail: int, refresh_key: int) -> pd.DataFrame:
    lines = tail_lines(LOG_PATH, max_tail)
    return parse_eve(lines)

def force_rerun():
    # Streamlit >=1.27 pakai st.rerun(); fallback jika perlu
    try:
        st.rerun()
    except Exception:
        pass

# ====== UI ======
st.title("🛡️ Suricata Monitoring")
st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS** — dashboard ini menampilkan log Suricata (eve.json), grafik cepat, dan unduhan CSV/JSON.")

with st.sidebar:
    st.subheader("Demo credentials (Basic Auth di Caddy)")
    st.code("fox   / foxziemalam999\nadit  / aditidn123\nbebek / bebekcantik123", language="text")
    st.divider()
    st.write("Path aplikasi:", BASE_URL_PATH)
    max_tail = st.slider("Jumlah baris terakhir (tail)", 1000, 100000, MAX_TAIL, step=1000)
    auto = st.checkbox("Auto-refresh tiap 5 detik", value=False)
    if st.button("Refresh sekarang"):
        # bump session tick
        st.session_state["tick"] = st.session_state.get("tick", 0) + 1
        force_rerun()

# autorefresh sederhana
if auto:
    # tambahkan anchor supaya cache key berubah
    st.session_state["tick"] = int(time.time() // 5)

tick = st.session_state.get("tick", 0)
df = load_df(max_tail, tick)

tab_overview, tab_live, tab_download = st.tabs(["Overview", "Live Logs", "Unduh"])

with tab_overview:
    col1, col2, col3 = st.columns(3)
    col1.metric("Total event (tail)", len(df))
    if not df.empty:
        top_evt = df["event_type"].value_counts().head(1)
        col2.metric("Event teratas", f"{top_evt.index[0]} ({int(top_evt.iloc[0])})")
        alerts = df[df["event_type"] == "alert"]
        col3.metric("Alert (tail)", len(alerts))
    st.divider()

    if not df.empty:
        st.subheader("Distribusi event type")
        vc = df["event_type"].value_counts().reset_index()
        vc.columns = ["event_type", "count"]
        st.bar_chart(vc.set_index("event_type"))

        if "src_ip" in df.columns and "dest_ip" in df.columns:
            st.subheader("Top src → dest (count)")
            agg = (df.groupby(["src_ip","dest_ip"])
                     .size().reset_index(name="count")
                     .sort_values("count", ascending=False).head(20))
            st.dataframe(agg, use_container_width=True, height=320)

with tab_live:
    st.subheader("Live logs (tail)")
    if df.empty:
        st.info(f"Tidak ada data. Pastikan log tersedia di: `{LOG_PATH}`")
    else:
        # filter ringkas
        c1, c2, c3, c4 = st.columns([1,1,1,2])
        evt = c1.multiselect("event_type", sorted(df["event_type"].dropna().unique().tolist()))
        proto = c2.multiselect("proto", sorted(df["proto"].dropna().unique().tolist())) if "proto" in df.columns else []
        q = c3.text_input("cari IP / signature", "")
        n = c4.slider("tampilkan N baris terakhir", 100, min(5000, len(df)), min(1000, len(df)), 100)

        view = df.copy()
        if evt:   view = view[view["event_type"].isin(evt)]
        if proto: view = view[view["proto"].isin(proto)]
        if q:
            ql = q.lower()
            cols = [c for c in ["src_ip","dest_ip","alert_signature"] if c in view.columns]
            if cols:
                mask = False
                for c in cols:
                    mask = mask | view[c].astype(str).str.lower().str.contains(ql, na=False)
                view = view[mask]
        view = view.tail(n)

        st.dataframe(view, use_container_width=True, height=420)

with tab_download:
    st.subheader("Unduh data (tail yang sudah difilter manual di atas tidak ikut — paket penuh)")
    if df.empty:
        st.info("Belum ada data untuk diunduh.")
    else:
        # paket JSONL & CSV dari tail penuh
        jsonl = "\n".join(df.to_dict(orient="records").__iter__().__str__())  # placeholder; di bawah kita generate benar
        # generate JSONL dan CSV yang proper
        import io
        jsonl_io = io.StringIO()
        for _, row in df.iterrows():
            jsonl_io.write(json.dumps(row.to_dict(), default=str) + "\n")
        csv_io = io.StringIO()
        df.to_csv(csv_io, index=False)

        st.download_button("Unduh JSON Lines (eve_tail.jsonl)", data=jsonl_io.getvalue(), file_name="eve_tail.jsonl", mime="application/json")
        st.download_button("Unduh CSV (eve_tail.csv)", data=csv_io.getvalue(), file_name="eve_tail.csv", mime="text/csv")

# footer kecil
st.caption(f"Log path: `{LOG_PATH}` · baseUrlPath: `{BASE_URL_PATH}`")
PY

# --- 2) Pastikan Caddy mengirim user ke upstream (opsional) & route /monitor tidak strip_prefix ---
say "Terapkan header X-Remote-User (opsional) & route /monitor..."
cp -a "$CADDYFILE" "$CADDYFILE.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
# patch minimal: pastikan block /monitor ada & tidak strip_prefix; tambah header_up
if ! grep -q 'handle_path /monitor' "$CADDYFILE" && ! grep -q 'handle /monitor' "$CADDYFILE"; then
  warn "Tidak menemukan blok /monitor di Caddyfile. Lewati patch header."
else
  # sisipkan header_up jika belum ada
  if ! grep -q 'header_up X-Remote-User' "$CADDYFILE"; then
    sed -ri '/reverse_proxy[[:space:]]+streamlit-app:8501/{
      N
      s/reverse_proxy[^\n]*/& {\n    header_up X-Remote-User {http.auth.user.id}\n  }/
    }' "$CADDYFILE" || true
  fi
fi

# Format via container temp
docker run --rm -v "$ROOT/caddy:/etc/caddy" caddy:2 caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null || true

# --- 3) Rebuild & restart services yang perlu ---
say "Build & restart Streamlit + publish frontend ke webroot..."
docker compose -f "$COMPOSE" up -d streamlit-app frontend-builder caddy-rev
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc \
  'npm run build >/dev/null 2>&1 || npm run build; rm -rf /webroot/* && cp -r dist/* /webroot/'

# reload caddy
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

# --- 4) Self test origin ---
say "Self-test origin:"
curl -s -o /dev/null -w "  /healthz         : %{http_code}\n" http://127.0.0.1:8080/healthz || true
curl -s -o /dev/null -w "  /                : %{http_code}\n" http://127.0.0.1:8080/ || true
curl -s -o /dev/null -w "  /monitor         : %{http_code}\n" http://127.0.0.1:8080/monitor || true
curl -s -o /dev/null -w "  /monitor(+auth)  : %{http_code}\n" -L -u fox:foxziemalam999 http://127.0.0.1:8080/monitor || true

ok "Selesai patch Streamlit + Caddy + Frontend."
