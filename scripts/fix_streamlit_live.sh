#!/usr/bin/env bash
# fix_streamlit_live.sh
# Patch Streamlit app agar live & kompatibel (st.rerun), plus dashboard/log/download.
set -euo pipefail

# --- Lokasi proyek (jalankan dari folder cloudflared) ---
BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"
APP_HOST="${APP_HOST:-$BASE/streamlit/app/app.py}"
APP_IN_CONTAINER="/app/app/app.py"
SERVICE="streamlit-app"

die(){ echo "ERR: $*" >&2; exit 1; }

[ -f "$COMPOSE" ] || die "docker-compose.yml tidak ditemukan di: $COMPOSE (jalankan dari folder cloudflared)."

TS="$(date +%Y%m%d_%H%M%S)"

echo ">> Pastikan stack hidup..."
docker compose -f "$COMPOSE" up -d $SERVICE >/dev/null

# --- Backup & tulis app.py di host (jika ada) ---
if [ -f "$APP_HOST" ]; then
  cp -a "$APP_HOST" "$APP_HOST.bak.$TS"
  echo ">> Backup host: $APP_HOST.bak.$TS"
else
  echo "WARN: Source host $APP_HOST tidak ada. Tetap akan injek ke container."
fi

# --- Konten app.py baru ---
read -r -d '' PYCODE <<'PY'
# app.py — Monitoring Suricata (ID-NETWORKERS)
import os, json, io, time, math, pathlib, sys
from collections import deque
import pandas as pd
import streamlit as st

# Altair opsional; fallback ke st.* chart
HAS_ALTAIR = True
try:
    import altair as alt   # type: ignore
except Exception:
    HAS_ALTAIR = False

st.set_page_config(page_title="Monitoring Suricata", layout="wide")

st.title("Monitoring Suricata")
st.caption("Untuk menyelesaikan tugas akhir dari **ID-NETWORKERS**")

# ---------- Konfigurasi ----------
EVE_PATH = os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
DEFAULT_LINES = int(os.environ.get("EVE_TAIL_LINES", "1500"))

# ---------- Util ----------
def force_rerun():
    try:
        st.rerun()
    except Exception:
        pass

def _tail_bytes(fp, max_lines=DEFAULT_LINES, chunk=1<<16):
    """
    Tail efisien: baca dari belakang sampai dapat ~max_lines baris JSON.
    """
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    buf = b""
    lines = []
    pos = size
    while pos > 0 and len(lines) <= max_lines:
        read = min(chunk, pos)
        pos -= read
        fp.seek(pos)
        buf = fp.read(read) + buf
        # split ke baris
        parts = buf.split(b"\n")
        buf = parts[0]  # sisa head
        lines = parts[1:] + lines
    # gabungkan sisa head bila valid json line
    if buf.strip():
        lines = [buf] + lines
    # ambil terakhir max_lines
    return lines[-max_lines:]

def load_eve(path: str, max_lines: int):
    p = pathlib.Path(path)
    if not p.exists():
        return pd.DataFrame(), {"exists": False, "size": 0, "path": path}
    size = p.stat().st_size
    objs = []
    with p.open("rb") as f:
        raw_lines = _tail_bytes(f, max_lines=max_lines)
        for b in raw_lines:
            if not b.strip():
                continue
            try:
                o = json.loads(b.decode("utf-8", "ignore"))
                objs.append(o)
            except Exception:
                # abaikan baris rusak
                pass
    df = pd.json_normalize(objs, max_level=2) if objs else pd.DataFrame()
    meta = {"exists": True, "size": size, "path": str(p), "rows": len(df)}
    return df, meta

def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    if df.empty: 
        return b""
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")

# ---------- Sidebar ----------
with st.sidebar:
    st.subheader("Kontrol")
    eve_path_input = st.text_input("Lokasi eve.json", value=EVE_PATH, help="Default: /var/log/suricata/eve.json")
    lines = st.slider("Tail baris (terakhir)", 100, 10000, DEFAULT_LINES, step=100)
    colA, colB = st.columns(2)
    with colA:
        auto = st.checkbox("Auto-refresh", value=False)
    with colB:
        interval = st.number_input("Detik", min_value=2, max_value=60, value=5, step=1)

    st.markdown("---")
    st.caption("🔐 Akses dilindungi Basic Auth di reverse proxy (Caddy).")

# ---------- Muat Data ----------
df, meta = load_eve(eve_path_input, max_lines=lines)

if not meta.get("exists", False):
    st.error(f"File tidak ditemukan: **{eve_path_input}**")
else:
    st.info(f"File: `{meta['path']}` • ukuran: {meta['size']:,} bytes • baris dimuat: {meta.get('rows',0)}")

# ---------- Tabs ----------
tab_dash, tab_logs, tab_dl = st.tabs(["📊 Dashboard", "📜 Logs", "⬇️ Download"])

with tab_dash:
    if df.empty:
        st.warning("Belum ada data.")
    else:
        # Timestamp normalisasi
        tscol = None
        for c in ["timestamp", "event_type.ts", "@timestamp"]:
            if c in df.columns:
                tscol = c; break
        if tscol:
            try:
                dt = pd.to_datetime(df[tscol], errors="coerce")
                df["_minute"] = dt.dt.floor("min")
            except Exception:
                df["_minute"] = pd.NaT
        else:
            df["_minute"] = pd.NaT

        # Hitung hanya alert
        if "event_type" in df.columns:
            alerts = df[df["event_type"] == "alert"].copy()
        else:
            alerts = df.copy()

        # Top signature
        sig_col = None
        for c in ["alert.signature", "alert.signature_id", "alert.signature.keyword"]:
            if c in df.columns:
                sig_col = c; break

        c1, c2, c3 = st.columns([2,2,1])
        with c1:
            if "_minute" in df.columns and df["_minute"].notna().any():
                agg = alerts.groupby("_minute").size().reset_index(name="count")
                st.caption("Alert per menit")
                if HAS_ALTAIR:
                    import altair as alt
                    ch = alt.Chart(agg).mark_line(point=True).encode(
                        x="{}_minute:T".format(""),
                        y="count:Q",
                        tooltip=["_minute:T","count:Q"]
                    ).properties(height=220)
                    st.altair_chart(ch, use_container_width=True)
                else:
                    agg = agg.set_index("_minute")
                    st.line_chart(agg["count"])
            else:
                st.info("Kolom timestamp tidak tersedia.")

        with c2:
            if sig_col:
                top = (alerts.groupby(sig_col).size()
                              .reset_index(name="count")
                              .sort_values("count", ascending=False).head(10))
                st.caption("Top 10 Signature")
                if HAS_ALTAIR:
                    ch = alt.Chart(top).mark_bar().encode(
                        x="count:Q", y=alt.Y(f"{sig_col}:N", sort="-x"),
                        tooltip=[sig_col,"count"]
                    ).properties(height=220)
                    st.altair_chart(ch, use_container_width=True)
                else:
                    st.bar_chart(top.set_index(sig_col)["count"])
            else:
                st.info("Kolom signature tidak tersedia.")

        with c3:
            sev_col = "alert.severity" if "alert.severity" in alerts.columns else None
            if sev_col:
                sev = (alerts.groupby(sev_col).size()
                              .reset_index(name="count")
                              .sort_values(sev_col))
                st.metric("Total Alert", int(sev["count"].sum()))
                st.dataframe(sev, use_container_width=True, height=220)
            else:
                st.metric("Total Event", int(len(df)))

with tab_logs:
    st.caption("Tail log (terbaru di bawah)")
    if df.empty:
        st.info("Tidak ada data untuk ditampilkan.")
    else:
        # Pilih kolom ringkas
        cols_pref = [c for c in ["timestamp","event_type","src_ip","src_port","dest_ip","dest_port","proto",
                                 "alert.signature","alert.severity","http.hostname","dns.rrname"] if c in df.columns]
        view = df[cols_pref] if cols_pref else df
        st.dataframe(view.tail(500), use_container_width=True, height=420)

with tab_dl:
    st.caption("Unduh data terakhir yang dimuat (tail)")
    c1, c2 = st.columns(2)
    with c1:
        st.download_button("⬇️ Download CSV", data=df_to_csv_bytes(df), file_name="eve_tail.csv", mime="text/csv", disabled=df.empty)
    with c2:
        raw = b""
        try:
            # Ambil raw tail JSON Lines utk download cepat
            p = pathlib.Path(eve_path_input)
            if p.exists():
                with p.open("rb") as f:
                    raw_lines = _tail_bytes(f, max_lines=lines)
                raw = b"\n".join(raw_lines)
        except Exception:
            pass
        st.download_button("⬇️ Download JSON (tail)", data=raw, file_name="eve_tail.json", mime="application/json", disabled=(raw==b""))

# ---------- Auto refresh ----------
if auto:
    time.sleep(int(interval))
    force_rerun()
PY

# --- Tulis ke host (jika path ada) ---
if [ -d "$(dirname "$APP_HOST")" ]; then
  echo ">> Tulis app.py ke host: $APP_HOST"
  printf '%s\n' "$PYCODE" > "$APP_HOST"
else
  echo "WARN: Direktori host untuk $APP_HOST tidak ada, lewati penulisan host."
fi

# --- Injek langsung ke container agar efeknya instan ---
CID="$(docker compose -f "$COMPOSE" ps -q $SERVICE || true)"
if [ -n "$CID" ]; then
  echo ">> Injek app.py ke container ($SERVICE)..."
  docker compose -f "$COMPOSE" exec -T $SERVICE sh -lc "cat > '$APP_IN_CONTAINER' <<'PY'
$PYCODE
PY"
else
  echo "WARN: Container $SERVICE belum aktif; akan dihidupkan pada langkah berikut."
fi

# --- Restart service biar pasti reload ---
echo ">> Restart $SERVICE ..."
docker compose -f "$COMPOSE" restart $SERVICE >/dev/null

# --- Tes ringkas: endpoint Streamlit (via Caddy sudah diatur /monitor) tetap di-serve oleh Streamlit ---
echo ">> DONE. Buka dashboard di: /monitor"
echo "   - Tab Dashboard: grafik alert/minute, top signature"
echo "   - Tab Logs: tail 500 baris terakhir"
echo "   - Tab Download: CSV & JSON (tail)"
echo "   - Sidebar: auto-refresh live (2–60 detik)"
