#!/usr/bin/env bash
set -Eeuo pipefail

# --- Konfigurasi kredensial DEMO (sinkron Caddy & landing) ---
CREDS=("fox:foxziemalam999" "adit:aditidn123" "bebek:bebekcantik123")

# --- Autodetect compose file (root atau subfolder) ---
if [[ -f "cloudflared/docker-compose.yml" ]]; then
  COMPOSE="cloudflared/docker-compose.yml"
elif [[ -f "./docker-compose.yml" ]]; then
  COMPOSE="./docker-compose.yml"
else
  echo "!! Tidak menemukan docker-compose.yml" >&2
  exit 1
fi

SVC_STREAMLIT="streamlit-app"
SVC_CADDY="caddy-rev"
SVC_FE="frontend-builder"
CADDY_HOST_DIR="cloudflared/caddy"
CADDYFILE="$CADDY_HOST_DIR/Caddyfile"

say(){ printf ">> %s\n" "$*"; }

# -----------------------------
# 0) Pastikan stack hidup
# -----------------------------
say "Up stack..."
docker compose -f "$COMPOSE" up -d >/dev/null

CID_STREAMLIT="$(docker compose -f "$COMPOSE" ps -q "$SVC_STREAMLIT" || true)"
CID_CADDY="$(docker compose -f "$COMPOSE" ps -q "$SVC_CADDY" || true)"
CID_FE="$(docker compose -f "$COMPOSE" ps -q "$SVC_FE" || true)"
[[ -n "$CID_STREAMLIT" ]] || { echo "!! Container $SVC_STREAMLIT tidak ditemukan"; exit 2; }
[[ -n "$CID_CADDY" ]] || { echo "!! Container $SVC_CADDY tidak ditemukan"; exit 2; }
[[ -n "$CID_FE" ]] || { echo "!! Container $SVC_FE tidak ditemukan"; exit 2; }

# -----------------------------
# 1) Sinkron BASIC AUTH Caddy
# -----------------------------
say "Generate bcrypt hash (via caddy:2) & patch Caddyfile..."
mkdir -p "$CADDY_HOST_DIR"
AUTH_TMP="$(mktemp)"
{
  echo "(auth) {"
  echo "  basic_auth {"
  for kv in "${CREDS[@]}"; do
    usr="${kv%%:*}"
    pass="${kv#*:}"
    hash="$(docker run --rm caddy:2 caddy hash-password --algorithm bcrypt --plaintext "$pass")"
    printf "    %-6s %s\n" "$usr" "$hash"
  done
  echo "  }"
  echo "}"
} > "$CADDY_HOST_DIR/.auth.hashes"

# Tulis Caddyfile minimal yang valid & public landing, protect /monitor
cat > "$CADDYFILE" <<'CFG'
{
  auto_https off
  servers :80 {
    protocols h1 h2c
  }
}

(auth) {
  # Placeholder; akan digantikan sed -e '/(auth)/,/}/' di bawah
}

:80 {
  handle_path /healthz { respond "ok" 200 }

  # Streamlit Wajib Basic Auth; prefix /monitor dipertahankan
  handle /monitor* {
    import auth
    reverse_proxy streamlit-app:8501
  }

  # API contoh (jika ada backend), juga protect
  handle /api/* {
    import auth
    reverse_proxy tornado-web:8080
  }

  # Landing React (public)
  handle {
    root * /srv/www
    encode zstd gzip
    try_files {path} /index.html
    file_server
  }
}
CFG

# Sisipkan blok auth hasil hash
awk '
  BEGIN { repl=0 }
  /^\(auth\)/ { print; repl=1; next }
  repl==1 {
    # skip sampai ketemu }
    if ($0 ~ /^\}/) { repl=2; next }
    next
  }
  { print }
' "$CADDYFILE" > "$CADDYFILE.tmp"

# temp merge auth hashes ke Caddyfile.tmp
awk '1' "$CADDYFILE.tmp" > "$CADDYFILE"
sed -i '/^(auth)/,/^}/d' "$CADDYFILE"
# temp header + auth + footer
{
  # header sebelum (auth)
  awk 'BEGIN{p=1} /^\(auth\)/{p=0} p{print}' "$CADDYFILE.tmp"
  # auth baru
  cat "$CADDY_HOST_DIR/.auth.hashes"
  # footer setelah blok auth lama
  awk 'BEGIN{p=0} /^\(auth\)/{p=1;next} p{print}' "$CADDYFILE.tmp"
} > "$CADDYFILE.new" && mv "$CADDYFILE.new" "$CADDYFILE" && rm -f "$CADDYFILE.tmp"

# Format pakai image caddy (hindari RO filesystem)
docker run --rm -v "$PWD/$CADDY_HOST_DIR:/etc/caddy" caddy:2 caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null 2>&1 || true

say "Reload Caddy (fallback restart bila gagal)..."
if ! docker compose -f "$COMPOSE" exec -T "$SVC_CADDY" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  docker compose -f "$COMPOSE" restart "$SVC_CADDY" >/dev/null
fi

# -----------------------------
# 2) Redeploy STREAMLIT (parser & UI)
# -----------------------------
say "Deploy app.py & helper ke container (pakai docker exec tanpa -T)..."
docker exec "$CID_STREAMLIT" sh -lc 'mkdir -p /app/app'

# app.py – hanya 1x set_page_config dan import helper lokal
docker exec "$CID_STREAMLIT" sh -lc 'cat > /app/app/app.py <<'\''PY'\''
import streamlit as st
st.set_page_config(page_title="Suricata Monitor", layout="wide", initial_sidebar_state="collapsed")
from _live_tail_patch import render_live
render_live()
PY'

# helper – live tail + filter + export CSV/JSONL + auto refresh (key unik)
docker exec "$CID_STREAMLIT" sh -lc 'cat > /app/app/_live_tail_patch.py <<'\''PY'\''
import os, json, time, io
from collections import deque
from typing import Deque, Dict, Any, List, Tuple
import pandas as pd
import streamlit as st

LOG_PATH = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
TAIL_MAX = int(os.getenv("EVE_MAX_LINES", "10000"))
DEFAULT_WINDOW_MIN = int(os.getenv("EVE_WINDOW_MIN", "60"))
BASE_URL_PATH = os.getenv("STREAMLIT_BASEURL", "/monitor")
AUTO_MIN_SEC = int(os.getenv("EVE_AUTO_MIN_SEC", "2"))

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
        if not ln: continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        rows.append(_flatten_event(obj))
    if not rows:
        return pd.DataFrame(columns=[
            "timestamp","event_type","src_ip","src_port","dest_ip","dest_port",
            "proto","app_proto","signature","sig_id","severity","dns_query","dns_rrtype",
            "dns_rcode","http_host","http_url","http_status","flow_to_srv","flow_to_cli"
        ])
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        with pd.option_context("mode.chained_assignment", None):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce")
    return df

def df_filter(df: pd.DataFrame, event_type, sig_sub, src_sub, dst_sub, last_minutes):
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
        since = pd.Timestamp.utcnow() - pd.Timedelta(minutes=int(last_minutes))
        out = out[out["timestamp"] >= since]
    return out

def _file_status(path: str) -> Tuple[bool, str]:
    try:
        stt = os.stat(path)
        ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stt.st_mtime))
        return True, f"size={stt.st_size}B, mtime(UTC)={ts}"
    except FileNotFoundError:
        return False, "file not found"

def render_live():
    st.title("Monitoring Suricata")
    st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

    ok, status = _file_status(LOG_PATH)
    st.info(f"Source: `{LOG_PATH}` — {status}")

    with st.sidebar:
        st.header("Filter")
        et  = st.selectbox("Event Type", ["ALL","alert","dns","flow","http","tls","ssh","ftp"], index=0, key="flt_et")
        sig = st.text_input("Signature contains", key="flt_sig")
        src = st.text_input("Src IP contains", key="flt_src")
        dst = st.text_input("Dest IP contains", key="flt_dst")
        win = st.number_input("Window (minutes)", min_value=0, max_value=24*60, value=DEFAULT_WINDOW_MIN, step=1, key="flt_win")
        st.divider()
        auto = st.toggle("Auto refresh", value=False, key="auto_toggle")
        interval = st.number_input("Interval (sec)", min_value=AUTO_MIN_SEC, max_value=60, value=5, key="auto_int")
        st.caption("Gunakan manual **Refresh** bila Auto refresh dimatikan.")

    if st.button("Refresh sekarang", key="btn_refresh_top"):
        st.rerun()

    if not ok:
        st.warning("File belum ada. Pastikan Suricata menulis `eve.json` ke path di atas.")
        return

    lines = tail_lines(LOG_PATH, TAIL_MAX)
    df = parse_eve_lines(lines)
    dff = df_filter(df, et, sig, src, dst, win if win and int(win) > 0 else None)

    c1,c2,c3,c4 = st.columns(4)
    with c1: st.metric("Total events (tail)", len(df))
    with c2: st.metric("Filtered", len(dff))
    with c3:
        alerts = (dff["event_type"] == "alert").sum() if "event_type" in dff else 0
        st.metric("Alerts (filtered)", int(alerts))
    with c4:
        sev2p = dff.query("severity >= 2").shape[0] if "severity" in dff.columns else 0
        st.metric("Severity ≥ 2", int(sev2p))

    if not dff.empty:
        a,b = st.columns(2)
        with a:
            by_type = dff["event_type"].value_counts().sort_values(ascending=False)
            st.subheader("Events by type")
            st.bar_chart(by_type)
        with b:
            if "signature" in dff.columns:
                top_sig = dff["signature"].fillna("unknown").value_counts().head(10)
                st.subheader("Top signatures")
                st.bar_chart(top_sig)

    st.subheader("Data (filtered)")
    st.dataframe(
        dff.sort_values("timestamp", ascending=False, na_position="last").head(200),
        use_container_width=True,
        hide_index=True,
    )

    csv_io = io.StringIO(); dff.to_csv(csv_io, index=False)
    st.download_button("Download CSV (filtered)", data=csv_io.getvalue(),
                       file_name="eve_filtered.csv", mime="text/csv", key="dl_csv")

    jsonl_io = io.StringIO()
    for _, row in dff.iterrows():
        payload = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        jsonl_io.write(json.dumps(payload, default=str) + "\n")
    st.download_button("Download JSONL (filtered)", data=jsonl_io.getvalue(),
                       file_name="eve_filtered.jsonl", mime="application/json", key="dl_jsonl")

    st.subheader("Tail (last 20 raw lines)")
    preview = "\n".join(lines[-20:])
    st.code(preview, language="json")

    if auto:
        time.sleep(max(AUTO_MIN_SEC, int(interval)))
        st.rerun()
PY'

say "Restart streamlit..."
docker compose -f "$COMPOSE" restart "$SVC_STREAMLIT" >/dev/null

# -----------------------------
# 3) Build & publish FRONTEND
# -----------------------------
say "Build & publish frontend Vite..."
docker compose -f "$COMPOSE" exec -T "$SVC_FE" sh -lc '
set -e
if [ -f package-lock.json ] || [ -d node_modules ]; then npm i >/dev/null 2>&1 || npm i; fi
npm run build
rm -rf /webroot/* && cp -r dist/* /webroot/
' >/dev/null

# -----------------------------
# 4) Self tests
# -----------------------------
say "Self-test origin (Caddy 127.0.0.1:8080)..."
echo -n "  /healthz : "; curl -sI http://127.0.0.1:8080/healthz | sed -n '1p'
echo -n "  /        : "; curl -sI http://127.0.0.1:8080/        | sed -n '1p'
echo -n "  /monitor : "; curl -sI http://127.0.0.1:8080/monitor | sed -n '1p'

say "Tail log streamlit (40 baris):"
docker compose -f "$COMPOSE" logs -n 40 "$SVC_STREAMLIT" || true

say "Selesai ✔"
