#!/usr/bin/env bash
# hotfix_streamlit_and_frontend.sh
set -euo pipefail

BASE="${BASE:-$PWD}"
COMPOSE="${COMPOSE:-$BASE/docker-compose.yml}"
SVC_S="streamlit-app"
SVC_F="frontend-builder"
APPDIR_CONT="/app/app"
APP_CONT="$APPDIR_CONT/app.py"

echo ">> Compose: $COMPOSE"
[ -f "$COMPOSE" ] || { echo "ERR: compose file tidak ketemu"; exit 1; }

echo ">> Pastikan stack hidup..."
docker compose -f "$COMPOSE" up -d >/dev/null

CID_S="$(docker compose -f "$COMPOSE" ps -q $SVC_S)"
CID_F="$(docker compose -f "$COMPOSE" ps -q $SVC_F)"
[ -n "$CID_S" ] || { echo "ERR: container $SVC_S belum jalan"; exit 1; }
[ -n "$CID_F" ] || { echo "ERR: container $SVC_F belum jalan"; exit 1; }

###############################################################################
# STREAMLIT: fix import, package, live tail, dan experimental_rerun
###############################################################################
echo ">> Patch Streamlit: jadikan package + inject live tail + fix rerun..."
docker compose -f "$COMPOSE" exec -T "$SVC_S" sh -lc "
  set -e
  test -f '$APP_CONT' || { echo 'ERR: $APP_CONT tidak ada'; exit 1; }
  cp -a '$APP_CONT' '${APP_CONT}.bak.$(date +%Y%m%d_%H%M%S)' || true
  # jadikan /app/app sebagai package
  [ -f '$APPDIR_CONT/__init__.py' ] || : > '$APPDIR_CONT/__init__.py'
  # tulis helper live tail (quoted supaya tidak diexpand shell)
  cat > '$APPDIR_CONT/_live_tail_patch.py' <<'PY'
import os, time, json, pathlib
import streamlit as st
from collections import deque

EVE_PATH = os.environ.get('EVE_PATH', '/var/log/suricata/eve.json')

def _read_last_lines(path, n=300):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    dq = deque(maxlen=n)
    with p.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if s:
                dq.append(s)
    return list(dq)

def render_live():
    st.set_page_config(page_title='Suricata Monitor', layout='wide')
    st.header('Monitoring Suricata')
    st.caption('Untuk menyelesaikan tugas akhir dari ID-NETWORKERS')

    with st.expander('Kredensial Akses (Basic Auth via Caddy)'):
        st.code('fox / foxziemalam999\\nadit / aditidn123\\nbebek / bebekcantik123', language='bash')
        st.warning('Jangan tampilkan ini di produksi.')

    colA, colB = st.columns([3,1])
    with colB:
        auto = st.toggle('Live refresh', value=True)
        every = st.number_input('Refresh (detik)', 1, 30, 2)
        limit = st.slider('Baris terakhir', 50, 2000, 300, 50)
        q = st.text_input('Filter (substring)', '', placeholder='event_type:alert atau src_ip=192.168.1.10')
    with colA:
        st.markdown(f'**File:** `{EVE_PATH}`')

    # ambil data
    raw_lines = _read_last_lines(EVE_PATH, n=limit)
    rows = []
    alerts = 0
    for s in raw_lines:
        try:
            obj = json.loads(s)
            if obj.get('event_type') == 'alert':
                alerts += 1
            rows.append(obj)
        except Exception:
            rows.append({'_raw': s})

    # filter sederhana (substring ke JSON dump)
    if q:
        ql = q.lower()
        filtered = []
        for r in rows:
            try:
                hay = json.dumps(r, ensure_ascii=False).lower()
            except Exception:
                hay = str(r).lower()
            if ql in hay:
                filtered.append(r)
        rows = filtered

    # metrik ringkas
    c1, c2, c3 = st.columns(3)
    c1.metric('Events ditampilkan', len(rows))
    c2.metric('Alerts', alerts)
    c3.metric('Last refresh', time.strftime('%H:%M:%S'))

    # tampilkan tabel
    try:
        import pandas as pd
        df = pd.json_normalize(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        # download
        st.download_button('Unduh CSV', data=df.to_csv(index=False), file_name='eve_subset.csv', mime='text/csv')
        st.download_button('Unduh JSONL', data='\\n'.join(json.dumps(r, ensure_ascii=False) for r in rows),
                           file_name='eve_subset.jsonl', mime='application/json')
    except Exception:
        st.write(rows)

    if auto:
        time.sleep(every)
        st.rerun()
PY

  # ganti import jadi lokal
  if grep -q '^from app\\._live_tail_patch import render_live' '$APP_CONT'; then
    sed -ri 's|^from app\\._live_tail_patch import render_live|from _live_tail_patch import render_live|' '$APP_CONT'
  fi
  # jika belum ada import, sisipkan di baris pertama
  if ! grep -q 'from _live_tail_patch import render_live' '$APP_CONT'; then
    sed -ri '1s|^|from _live_tail_patch import render_live\\n|' '$APP_CONT'
  fi
  # bersihkan experimental_rerun
  sed -ri '/st\\.experimental_rerun[[:space:]]*$/d' '$APP_CONT'
  sed -ri 's/st\\.experimental_rerun\\(/st.rerun(/g' '$APP_CONT'

  # pastikan ada panggilan render_live() di akhir file (tanpa dobel)
  if ! grep -q 'render_live\\(\\)' '$APP_CONT'; then
    printf '\\nif __name__ == \"__main__\":\\n    render_live()\\n' >> '$APP_CONT'
  fi
"
echo ">> Restart Streamlit..."
docker compose -f "$COMPOSE" restart "$SVC_S" >/dev/null

###############################################################################
# FRONTEND: sinkronkan App.jsx (punyamu) + CSS ciamik + build + publish
###############################################################################
echo ">> Patch Frontend (App.jsx + index.css) & build..."
docker compose -f "$COMPOSE" exec -T "$SVC_F" sh -lc "
  set -e
  cd /app

  # Tulis index.css (ciamik)
  cat > src/index.css <<'CSS'
:root{--bg:#0b1220;--fg:#e9eefc;--muted:#9fb2d9;--card:#121b31;--cta:#3b82f6;--ctaHover:#2563eb}
*{box-sizing:border-box}html,body,#root{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif}
.hero{display:flex;flex-direction:column;min-height:100%}
.topbar{position:sticky;top:0;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(6px)}
.brand{padding:14px 20px;font-weight:700;letter-spacing:.4px}
.wrap{max-width:920px;margin:clamp(32px,7vh,72px) auto;padding:0 20px;text-align:center}
h1{font-size:clamp(28px,6vw,48px);margin:0 0 10px;line-height:1.1}
.tagline{color:var(--muted);font-size:clamp(14px,2.5vw,18px);margin:0 auto 26px}
.bullets{list-style:none;padding:0;margin:10px auto 28px;display:inline-grid;gap:10px}
.bullets li{background:var(--card);border:1px solid rgba(255,255,255,.06);padding:10px 14px;border-radius:14px;color:#cfe0ff}
.cta{display:inline-block;margin-top:4px;background:var(--cta);color:#fff;text-decoration:none;padding:12px 18px;border-radius:12px;font-weight:700}
.cta:hover{background:var(--ctaHover)}
.foot{margin-top:auto;padding:20px;color:#91a7d7;opacity:.9;text-align:center;font-size:13px;border-top:1px dashed rgba(255,255,255,.08)}
/* responsive tweaks */
@media (max-width:640px){.brand{padding:12px 16px}.wrap{padding:0 14px}.bullets{grid-template-columns:1fr}}
CSS

  # Pastikan main.jsx import CSS
  if ! grep -q 'index.css' src/main.jsx 2>/dev/null; then
    sed -ri '1s|^|import \"./index.css\";\\n|' src/main.jsx
  fi

  # Pakai App.jsx yang kamu kirim
  cat > src/App.jsx <<'JS'
YOUR_APP_JS_WILL_BE_INJECTED_HERE
JS

  # deps wajib untuk App.jsx
  if ! node -e 'require.resolve(\"framer-motion\")' >/dev/null 2>&1; then npm install framer-motion@latest; fi
  if ! node -e 'require.resolve(\"lucide-react\")' >/dev/null 2>&1; then npm install lucide-react@latest; fi

  # build & publish
  (npm ci || npm install)
  npm run build
  rm -rf /webroot/* && cp -r dist/* /webroot/
"

# sisipkan konten App.jsx user (safe replace placeholder)
APP_JS_ESCAPED="$(python3 - <<'PY'
import sys, json
js = sys.stdin.read()
print(js)
PY
<<'APPJS'
import React from "react";
import { motion } from "framer-motion";
import { Activity, LineChart, ShieldAlert, Cloud, Download, Filter, Box, Lock, TerminalSquare, ArrowRight, Github, KeyRound, Cog, ExternalLink, CheckCircle2, Copy } from "lucide-react";

export default function App() {
  const creds = [
    { user: "fox", pass: "foxziemalam999" },
    { user: "adit", pass: "aditidn123" },
    { user: "bebek", pass: "bebekcantik123" },
  ];

  const copy = (text) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 selection:bg-emerald-500/30 selection:text-emerald-200">
      <div className="fixed inset-0 -z-10">
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_-10%,rgba(16,185,129,0.15),rgba(0,0,0,0))]" />
        <div className="absolute inset-0 bg-[radial-gradient(60%_40%_at_50%_110%,rgba(99,102,241,0.12),rgba(0,0,0,0))]" />
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
      </div>

      <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/40 border-b border-white/5">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="size-8 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30">
              <ShieldAlert className="size-5 text-emerald-400" />
            </div>
            <span className="font-semibold tracking-tight">Suricata Monitor</span>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm text-zinc-300">
            <a href="#fitur" className="hover:text-white">Fitur</a>
            <a href="#teknologi" className="hover:text-white">Teknologi</a>
            <a href="#demo" className="hover:text-white">Demo</a>
            <a href="#faq" className="hover:text-white">FAQ</a>
          </nav>
          <div className="flex items-center gap-3">
            <a href="/monitor" className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium bg-emerald-500 hover:bg-emerald-400 text-zinc-950 transition-colors">
              Masuk Dashboard <ArrowRight className="size-4" />
            </a>
          </div>
        </div>
      </header>

      <section className="relative">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-10 pt-16 pb-10">
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
              <h1 className="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">
                Monitoring <span className="text-emerald-400">Suricata</span>
              </h1>
              <p className="mt-4 text-lg text-zinc-300">
                Untuk menyelesaikan tugas akhir dari <b className="text-white">ID-NETWORKERS</b>. Dashboard menampilkan log <code className="text-emerald-300">eve.json</code>, grafik singkat, dan unduhan CSV/JSON.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <a href="/monitor" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium bg-emerald-500 hover:bg-emerald-400 text-zinc-950 transition-colors">
                  <TerminalSquare className="size-5" /> Masuk ke Dashboard
                </a>
                <a href="/docs" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium border border-white/10 hover:border-white/20">
                  <ExternalLink className="size-5" /> Dokumentasi
                </a>
                <a href="https://github.com/" className="inline-flex items-center gap-2 rounded-xl px-5 py-3 font-medium border border-white/10 hover:border-white/20">
                  <Github className="size-5" /> Source
                </a>
              </div>
              <div className="mt-10 grid grid-cols-3 gap-4 max-w-lg">
                {[
                  { icon: Activity, label: "Events/min", value: "~1.2k" },
                  { icon: ShieldAlert, label: "Alerts", value: "~230" },
                  { icon: LineChart, label: "Throughput", value: "~180 Mbps" },
                ].map((s) => (
                  <div key={s.label} className="rounded-2xl border border-white/10 p-4">
                    <div className="flex items-center gap-2 text-zinc-400 text-xs">
                      {React.createElement(s.icon, { className: "size-4 text-emerald-400" })}
                      {s.label}
                    </div>
                    <div className="mt-1 text-2xl font-semibold">{s.value}</div>
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.1 }}>
              <div className="relative rounded-3xl border border-white/10 bg-zinc-900/60 backdrop-blur p-4 lg:p-6 shadow-2xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-zinc-400">
                    <div className="size-2 rounded-full bg-rose-400" />
                    <div className="size-2 rounded-full bg-amber-400" />
                    <div className="size-2 rounded-full bg-emerald-400" />
                    <span className="ml-2">tail -f /var/log/suricata/eve.json</span>
                  </div>
                  <span className="text-xs text-zinc-400">Live</span>
                </div>
                <pre className="mt-4 h-72 overflow-auto rounded-2xl bg-black/60 p-4 text-xs leading-relaxed text-emerald-200/90">
{`{\"timestamp\":\"2025-08-11T14:22:10Z\",\"event_type\":\"alert\",\"src_ip\":\"192.168.10.5\",\"dest_ip\":\"10.10.10.12\",\"alert\":{\"signature\":\"ET WEB_SERVER Possible SQLi UNION SELECT\",\"severity\":2}}
{\"timestamp\":\"2025-08-11T14:22:11Z\",\"event_type\":\"dns\",\"query\":\"suspicious.example\",\"rrtype\":\"A\",\"rcode\":\"NOERROR\"}
{\"timestamp\":\"2025-08-11T14:22:12Z\",\"event_type\":\"flow\",\"app_proto\":\"http\",\"bytes_toserver\":9831,\"bytes_toclient\":12044}
`}
                </pre>
                <div className="mt-3 flex items-center justify-between text-xs text-zinc-400">
                  <div className="flex items-center gap-3">
                    <div className="inline-flex items-center gap-1"><Filter className="size-4 text-emerald-400" /> filter: <code>event_type:alert</code></div>
                    <div className="inline-flex items-center gap-1"><Download className="size-4 text-emerald-400" /> export: CSV · JSONL</div>
                  </div>
                  <div className="inline-flex items-center gap-1"><Cloud className="size-4 text-emerald-400" /> Cloudflared Tunnel</div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section id=\"fitur\" className=\"py-12 sm:py-16\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Fitur\" subtitle=\"Semua yang kamu butuhkan untuk observasi cepat\" />
          <div className=\"mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3\">
            <Feature icon={Filter} title=\"Live tail + filter\" desc=\"Streaming eve.json dengan query sederhana (event_type, src_ip, signature).\" />
            <Feature icon={LineChart} title=\"Grafik event & alert\" desc=\"Sparkline & mini chart untuk tren menit-an atau jam-an.\" />
            <Feature icon={Download} title=\"Unduh CSV & JSONL\" desc=\"Ambil subset data untuk analisis lanjutan di Python/R/SIEM.\" />
            <Feature icon={Lock} title=\"Basic Auth\" desc=\"Caddy reverse proxy dengan kredensial demo untuk akses cepat.\" />
            <Feature icon={Box} title=\"Ringan\" desc=\"Vite + React (landing), Streamlit 1.37 (Python 3.11) untuk UI log.\" />
            <Feature icon={Cloud} title=\"Tunnel\" desc=\"Expose lokal aman via Cloudflared Tunnel tanpa fixed IP.\" />
          </div>
        </div>
      </section>

      <section id=\"teknologi\" className=\"py-12 sm:py-16 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Teknologi\" subtitle=\"Komponen utama deployment\" />
          <div className=\"mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4\">
            {[
              { name: \"Streamlit 1.37\", icon: TerminalSquare },
              { name: \"Caddy Reverse Proxy\", icon: Lock },
              { name: \"Vite + React\", icon: Box },
              { name: \"Cloudflared Tunnel\", icon: Cloud },
            ].map((t) => (
              <div key={t.name} className=\"rounded-2xl border border-white/10 p-5 flex items-center gap-3\">
                {React.createElement(t.icon, { className: \"size-6 text-emerald-400\" })}
                <div>
                  <div className=\"font-medium\">{t.name}</div>
                  <div className=\"text-xs text-zinc-400\">Production-ready</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id=\"demo\" className=\"py-12 sm:py-16\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"Demo Credentials\" subtitle=\"Gunakan saat diminta Basic Auth (Caddy).\" />
          <div className=\"mt-6 grid gap-4 lg:grid-cols-2\">
            <div className=\"rounded-2xl border border-white/10 p-6\">
              <div className=\"text-sm text-zinc-400\">Akun Demo</div>
              <div className=\"mt-3 divide-y divide-white/5\">
                {[
                  {user:'fox',pass:'foxziemalam999'},
                  {user:'adit',pass:'aditidn123'},
                  {user:'bebek',pass:'bebekcantik123'}
                ].map((c)=>(
                  <div key={c.user} className=\"py-3 flex items-center justify-between\">
                    <div>
                      <div className=\"font-mono text-sm\">{c.user}</div>
                      <div className=\"text-xs text-zinc-400\">{c.pass}</div>
                    </div>
                    <button onClick={()=>navigator.clipboard.writeText(`${c.user}:${c.pass}`)} className=\"inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-1.5 text-xs hover:border-white/20\">
                      <Copy className=\"size-3.5\" /> salin
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className=\"rounded-2xl border border-white/10 p-6 bg-gradient-to-b from-white/5 to-transparent\">
              <div className=\"text-sm text-zinc-400\">Contoh Konfigurasi Caddy (Basic Auth)</div>
              <pre className=\"mt-3 text-xs bg-black/50 rounded-xl p-4 overflow-auto\">{`# Caddyfile
:80 {
  handle_path /monitor* {
    basic_auth { ... }
    reverse_proxy streamlit-app:8501
  }
}`}</pre>
            </div>
          </div>
        </div>
      </section>

      <section id=\"faq\" className=\"py-12 sm:py-16 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <SectionTitle title=\"FAQ\" subtitle=\"Pertanyaan umum terkait setup\" />
          <div className=\"mt-6 grid gap-4 lg:grid-cols-2\">
            <Faq q=\"Apakah butuh VPS?\" a=\"Tidak wajib. Bisa expose lokal via Cloudflared Tunnel.\" />
            <Faq q=\"Apakah data bisa di-export?\" a=\"Ya, unduh CSV/JSONL dari dashboard.\" />
            <Faq q=\"Autentikasi seperti apa?\" a=\"Basic Auth di layer proxy (Caddy).\" />
            <Faq q=\"Seberapa ringan?\" a=\"Landing Vite + React, backend Streamlit.\" />
          </div>
        </div>
      </section>

      <footer className=\"mt-10 border-t border-white/5\">
        <div className=\"mx-auto max-w-7xl px-4 sm:px-6 lg:px-8\">
          <div className=\"py-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-zinc-400\">
            <div className=\"flex items-center gap-2\">
              <CheckCircle2 className=\"size-4 text-emerald-400\" />
              <span>© {new Date().getFullYear()} Suricata Monitor • ID-NETWORKERS TA</span>
            </div>
            <div className=\"flex items-center gap-5\">
              <a href=\"/monitor\" className=\"hover:text-white inline-flex items-center gap-1\"><TerminalSquare className=\"size-4\" /> Dashboard</a>
              <a href=\"/docs\" className=\"hover:text-white inline-flex items-center gap-1\"><ExternalLink className=\"size-4\" /> Docs</a>
              <a href=\"https://github.com/\" className=\"hover:text-white inline-flex items-center gap-1\"><Github className=\"size-4\" /> GitHub</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function SectionTitle({ title, subtitle }) {
  return (
    <div className=\"max-w-2xl\">
      <h2 className=\"text-2xl font-semibold\">{title}</h2>
      <p className=\"mt-1 text-zinc-400\">{subtitle}</p>
    </div>
  );
}

function Feature({ icon: Icon, title, desc }) {
  return (
    <div className=\"rounded-2xl border border-white/10 p-5\">
      <div className=\"flex items-center gap-3\">
        <div className=\"size-9 grid place-items-center rounded-xl bg-emerald-500/15 ring-1 ring-emerald-400/30\">
          <Icon className=\"size-5 text-emerald-400\" />
        </div>
        <div>
          <div className=\"font-medium\">{title}</div>
          <div className=\"text-sm text-zinc-400\">{desc}</div>
        </div>
      </div>
    </div>
  );
}

function Faq({ q, a }) {
  return (
    <details className=\"rounded-2xl border border-white/10 p-5 group open:bg-white/[0.02]\">
      <summary className=\"cursor-pointer list-none flex items-center justify-between\">
        <span className=\"font-medium\">{q}</span>
        <span className=\"text-zinc-400 group-open:rotate-90 transition-transform\">›</span>
      </summary>
      <p className=\"mt-3 text-sm text-zinc-300\">{a}</p>
    </details>
  );
}
APPJS
)"
# inject App.jsx content
docker compose -f "$COMPOSE" exec -T "$SVC_F" sh -lc "perl -0777 -pe 's#YOUR_APP_JS_WILL_BE_INJECTED_HERE#\${APP_JS_ESCAPED}#s' -i /app/src/App.jsx" >/dev/null 2>&1 || true

echo ">> Reload Caddy..."
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

echo ">> Tes origin:"
curl -sI http://127.0.0.1:8080/healthz | head -n1 || true
curl -sI http://127.0.0.1:8080/        | head -n1 || true
curl -sI http://127.0.0.1:8080/monitor | head -n1 || true

echo ">> Done."
