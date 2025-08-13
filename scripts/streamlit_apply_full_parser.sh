#!/usr/bin/env bash
set -euo pipefail

COMPOSE="cloudflared/docker-compose.yml"
SVC="streamlit-app"

say(){ printf ">> %s\n" "$*"; }

# --- Sumber kode Python yang akan di-copy ke container ---
read -r -d '' APP_PY <<"PY"
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")

from _live_tail_patch import render_live

# Jalankan tampilan live dari helper
render_live()
PY

read -r -d '' HELPER_PY <<"PY"
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

# ======================
# Konfigurasi & konstanta
# ======================
LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))     # baca N baris terakhir
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")   # penting untuk Caddy path prefix
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))  # minimal interval auto refresh

# ======================
# Util
# ======================
def tail_lines(path: str, max_lines: int) -> List[str]:
    dq: Deque[str] = deque(maxlen=max_lines)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return []
    return list(dq)

def _flatten_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Ambil kolom umum dan flatten alert/dns/flow seminimal mungkin."""
    out: Dict[str, Any] = {}
    out["timestamp"]   = raw.get("timestamp")
    out["event_type"]  = raw.get("event_type")
    out["src_ip"]      = raw.get("src_ip")
    out["src_port"]    = raw.get("src_port")
    out["dest_ip"]     = raw.get("dest_ip")
    out["dest_port"]   = raw.get("dest_port")
    out["proto"]       = raw.get("proto")
    out["app_proto"]   = raw.get("app_proto")

    a = raw.get("alert") or {}
    out["signature"]   = a.get("signature")
    out["sig_id"]      = a.get("signature_id")
    out["severity"]    = a.get("severity")

    dns = raw.get("dns") or {}
    out["dns_query"]   = dns.get("rrname") or dns.get("query")
    out["dns_rrtype"]  = dns.get("rrtype")
    out["dns_rcode"]   = dns.get("rcode")

    http = raw.get("http") or {}
    out["http_host"]   = http.get("hostname")
    out["http_url"]    = http.get("url")
    out["http_status"] = http.get("status")

    flow = raw.get("flow") or {}
    out["flow_to_srv"] = flow.get("bytes_toserver")
    out["flow_to_cli"] = flow.get("bytes_toclient")

    return out

def parse_eve_lines(lines: List[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            # skip baris korup
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    # cast ringan
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame,
              event_type: str|None,
              sig_sub: str|None,
              src_sub: str|None,
              dst_sub: str|None,
              last_minutes: int|None) -> pd.DataFrame:
    out = df.copy()
    if event_type and event_type != "ALL":
        out = out[out["event_type"] == event_type]
    if sig_sub:
        out = out[out["signature"].fillna("").str.contains(sig_sub, case=False, na=False)]
    if src_sub:
        out = out[out["src_ip"].fillna("").str.contains(src_sub, case=False, na=False)]
    if dst_sub:
        out = out[out["dest_ip"].fillna("").str.contains(dst_sub, case=False, na=False)]
    if last_minutes and "timestamp" in out.columns and pd.api.types.is_datetime64_any_dtype(out["timestamp"]):
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=last_minutes)
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

# ======================
# UI utama
# ======================
def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    # Sidebar filters — beri key unik
    with st.sidebar:
        st.header("Filter")
        et = st.selectbox("Event Type", options=["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    # Tombol refresh dengan key unik agar tidak duplicate
    cols = st.columns([1,1,6])
    with cols[0]:
        if st.button("Refresh sekarang", key="btn_refresh_top"):
            st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    # Baca tail + parse
    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)

    # Terapkan filter
    dff = df_filter(df, et, sig, src, dst, win if win > 0 else None)

    # Ringkas atas
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    # Chart ringan
    if not dff.empty:
        cA, cB = st.columns(2)
        with cA:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with cB:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    # Data table
    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    # Downloads (subset saat ini)
    csv_io = io.StringIO()
    dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(), file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        # rebuild JSONL minimal dari kolom flatten
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(), file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    # Raw tail (beberapa baris terakhir)
    st.subheader("Tail (last 20 raw lines)")
    preview = "\n".join(lines[-20:])
    st.code(preview, language="json")

    # Auto refresh sederhana (tanpa lib eksternal)
    if auto:
        # Hindari loop ketat
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY
# --- END sources ---

if [[ ! -f "$COMPOSE" ]]; then
  echo "Compose file tidak ditemukan: $COMPOSE" >&2
  exit 1
fi

echo ">> Pastikan container $SVC up..."
docker compose -f "$COMPOSE" up -d "$SVC" >/dev/null

CID=$(docker compose -f "$COMPOSE" ps -q "$SVC")
if [[ -z "$CID" ]]; then
  echo "Container $SVC tidak ditemukan" >&2
  exit 2
fi

echo ">> Deploy app.py & helper ke container..."
docker exec -i "$CID" sh -lc 'mkdir -p /app/app'
printf "%s" "$APP_PY"   | docker exec -i "$CID" sh -lc 'cat > /app/app/app.py'
printf "%s" "$HELPER_PY"| docker exec -i "$CID" sh -lc 'cat > /app/app/_live_tail_patch.py'

echo ">> Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC" >/dev/null

echo ">> Quick log (tail 40):"
docker compose -f "$COMPOSE" logs -n 40 "$SVC" || true

echo ">> Cek cepat (origin via Caddy):"
curl -sI http://127.0.0.1:8080/monitor | head -n1 || true
echo "Selesai ✓"
