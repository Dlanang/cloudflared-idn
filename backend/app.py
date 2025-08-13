# app.py - Streamlit Suricata monitor (Layer2: SHA-256), KISS
# app.py - Streamlit Suricata monitor (Layer2: SHA-256), KISS
import streamlit as st
import pandas as pd
import json, hashlib, io, time
from pathlib import Path

# --- helper: safe resample per minute ---
def _resample_per_minute(df, ts_candidates=("timestamp","@timestamp","time","ts","event_time")):
    import pandas as pd
    if df is None:
        return pd.Series(dtype="int64")
    # Series -> DataFrame
    if isinstance(df, pd.Series):
        df = df.to_frame()
    # Sudah DatetimeIndex?
    try:
        import pandas as pd  # ensure
        from pandas import DatetimeIndex  # noqa
        if isinstance(getattr(df, "index", None), pd.DatetimeIndex):
            return _resample_per_minute(df)
    except Exception:
        pass
    # Cari kolom timestamp umum
    for c in ts_candidates:
        if isinstance(df, pd.DataFrame) and c in df.columns:
            ts = pd.to_datetime(df[c], errors="coerce", utc=True)
            df2 = df.loc[ts.notna()].copy()
            if df2.empty:
                return pd.Series(dtype="int64")
            df2["_ts"] = ts[ts.notna()]
            df2 = df2.set_index("_ts")
            try:
                return df2.resample("1T").size()
            except Exception:
                continue
    # Gagal semua -> return seri kosong
    return pd.Series(dtype="int64")
# --- end helper ---


PROJECT_DIR = Path(__file__).parent
CREDS_FILE = PROJECT_DIR / "creds.json"
IMAGE_FILE = PROJECT_DIR / "image.png"
LOG_FILE_DEFAULT = "/var/log/suricata/eve.json"

st.set_page_config(page_title="Final Task Monitoring Suricata", layout="wide")

def load_creds():
    if CREDS_FILE.exists():
        return json.loads(CREDS_FILE.read_text())
    return {}

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def show_login():
    if IMAGE_FILE.exists():
        st.image(str(IMAGE_FILE), width=140)
    st.markdown("# Final Task Monitoring Suricata")
    st.markdown("Projek ini ditujukan sebagai tugas terakhir bootcamp noctra lupra dari ID-NETWORKERS dijalankan di server 1 core 1 gb ram untuk memperoleh log trafik")
    st.markdown("---")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        creds = load_creds()
        if u in creds and creds[u] == sha256_hex(p):
            st.session_state.auth = True
            st.session_state.user = u
            st.rerun()
        else:
            st.error("Login gagal — cek username/password.")

def read_last_lines(path, max_lines=500):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, "rb") as f:
        f.seek(0, 2)
        filesize = f.tell()
        block = 8192
        data = b""
        lines = []
        while len(lines) <= max_lines and filesize > 0:
            start = max(0, filesize-block)
            f.seek(start)
            data = f.read(min(block, filesize)) + data
            filesize = start
            lines = data.splitlines()
    text_lines = [ln.decode(errors="ignore") for ln in lines[-max_lines:]]
    objs = []
    for ln in text_lines:
        ln = ln.strip()
        if not ln: 
            continue
        try:
            objs.append(json.loads(ln))
        except Exception:
            continue
    return objs

if "auth" not in st.session_state:
    st.session_state.auth = False

if not st.session_state.auth:
    show_login()
else:
    st.sidebar.markdown(f"**User:** {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.auth = False
        st.session_state.user = None
        st.rerun()

    st.title("Suricata — Live Logs & Quick Stats")
    log_path = st.sidebar.text_input("eve.json path", LOG_FILE_DEFAULT)
    tail_lines = st.sidebar.number_input("Lines to display", min_value=10, max_value=2000, value=200)
    only_alerts = st.sidebar.checkbox("Only alerts", value=False)
    filter_q = st.sidebar.text_input("Filter (key:value or free text)", "")
    refresh = st.sidebar.number_input("Auto-refresh (s, 0 disable)", min_value=0, max_value=30, value=5)

    LOG_FILE = Path(log_path).expanduser().as_posix()
    lines = read_last_lines(LOG_FILE, max_lines=2000)
    df = pd.json_normalize(lines) if lines else pd.DataFrame()
    if df.empty:
        st.warning("No logs found or file empty.")
    else:
        df_display = df.copy()
        if only_alerts and "event_type" in df_display.columns:
            df_display = df_display[df_display["event_type"] == "alert"]
        if filter_q:
            if ":" in filter_q:
                k,v = filter_q.split(":",1)
                k=k.strip(); v=v.strip()
                if k in df_display.columns:
                    df_display = df_display[df_display[k].astype(str).str.contains(v, case=False, na=False)]
            else:
                mask = pd.Series(False, index=df_display.index)
                for c in df_display.select_dtypes(include=["object"]).columns:
                    mask = mask | df_display[c].astype(str).str.contains(filter_q, case=False, na=False)
                df_display = df_display[mask]
        if "timestamp" in df_display.columns:
            df_display = df_display.sort_values("timestamp", ascending=False)

        st.write(f"Showing {len(df_display)} rows (of {len(df)} total).")
        st.dataframe(df_display.head(tail_lines), height=600)

        st.markdown("### Quick stats")
        c1,c2,c3 = st.columns(3)
        with c1:
            if "event_type" in df.columns:
                st.bar_chart(df["event_type"].value_counts())
        with c2:
            for ipcol in ("src_ip","dest_ip"):
                if ipcol in df.columns:
                    st.write(f"Top {ipcol}")
                    st.table(df[ipcol].value_counts().head(8).rename_axis(ipcol).reset_index(name="count"))
                    break
        with c3:
            if "timestamp" in df.columns:
                tmp = df.dropna(subset=["timestamp"]).set_index("timestamp")
                st.line_chart(_resample_per_minute(tmp).tail(60))

        csv_buf = io.StringIO()
        df_display.to_csv(csv_buf, index=False)
        st.download_button("Download filtered CSV", data=csv_buf.getvalue(), file_name="suricata_filtered.csv", mime="text/csv")

    if refresh > 0:
        time.sleep(refresh)
        st.rerun()
