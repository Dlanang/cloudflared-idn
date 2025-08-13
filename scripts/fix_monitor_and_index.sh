#!/usr/bin/env bash
set -euo pipefail

# --- Locate compose file ---
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${BASE_DIR}/docker-compose.yml" ]]; then
  COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
elif [[ -f "${BASE_DIR}/cloudflared/docker-compose.yml" ]]; then
  COMPOSE_FILE="${BASE_DIR}/cloudflared/docker-compose.yml"
else
  echo "ERR: docker-compose.yml tidak ditemukan di ${BASE_DIR} atau ${BASE_DIR}/cloudflared"
  exit 1
fi
COMPOSE="docker compose -f ${COMPOSE_FILE}"

# --- Project & volume name ---
PROJECT="$($COMPOSE config 2>/dev/null | awk '/^name:/{print $2; exit}' || true)"
PROJECT="${PROJECT:-monitoring_stack}"
VOL_WEBROOT="${PROJECT}_webroot"
VOL_SURI_LOGS="${PROJECT}_suri_logs"

echo ">> Compose file: ${COMPOSE_FILE}"
echo ">> Project: ${PROJECT}"
echo ">> Volumes: ${VOL_WEBROOT}, ${VOL_SURI_LOGS}"

echo ">> Pastikan stack jalan..."
$COMPOSE up -d --build

# --- Patch file HTML agar Rocket Loader tidak ganggu ---
echo ">> Patch bundle HTML agar bypass Rocket Loader..."
docker run --rm -v "${VOL_WEBROOT}:/webroot" busybox sh -euxc '
  # Cari semua *.html lalu patch:
  find /webroot -type f -name "*.html" 2>/dev/null | while IFS= read -r f; do
    # Tambah data-cfasync="false" supaya Rocket Loader nggak utak-atik script tag
    sed -ri "s@<script @<script data-cfasync=\"false\" @g" "$f"
    # Ubah type yang di-hash oleh Rocket Loader kembali ke module
    sed -ri "s@type=\"[^\"]*-module\"@type=\"module\"@g" "$f"
  done
'

# --- Landing SPA + healthz ---
echo ">> Simpan index lama (jika ada) & buat landing SPA..."
docker run --rm -v "${VOL_WEBROOT}:/webroot" busybox sh -lc '
  if [ -f /webroot/index.html ] && [ ! -f /webroot/index.react.html ]; then
    mv /webroot/index.html /webroot/index.react.html
  fi
  cat > /webroot/index.html <<EOF
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Monitoring</title>
  <style>
    html,body{margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;background:#0b1220;color:#e7eef7}
    .wrap{max-width:880px;margin:6vh auto;padding:24px}
    .card{background:#111a2e;border:1px solid #203055;border-radius:18px;padding:24px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    h1{margin:0 0 12px;font-size:28px} p.lead{opacity:.9;margin:0 0 16px}
    .grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:16px}
    a.btn{display:block;text-decoration:none;text-align:center;padding:12px 16px;border-radius:12px;border:1px solid #2b3f6a;background:#1a2a4a;color:#e7eef7;transition:all .15s}
    a.btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,0,0,.25)}
    small{opacity:.7}.ok{color:#8ef59f}.bad{color:#ff9a9a} code{background:#0c1426;border:1px solid #1e2d52;border-radius:8px;padding:2px 6px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Monitoring Suricata</h1>
      <p class="lead"><strong>Untuk menyelesaikan tugas akhir dari ID-NETWORKERS</strong></p>
      <p>Data Suricata dipresentasikan dengan <em>Streamlit</em> di <code>/monitor</code>. Anda juga bisa mengunduh <code>eve.json</code> atau <code>eve.csv</code>.</p>
      <div id="health"></div>
      <div class="grid">
        <a class="btn" href="/monitor">Buka Monitor (Streamlit)</a>
        <a class="btn" href="/eve.json" download>Unduh EVE (JSON)</a>
        <a class="btn" href="/eve.csv" download>Unduh EVE (CSV)</a>
        <a class="btn" href="/index.react.html">Versi React (jika ada)</a>
      </div>
      <p style="margin-top:16px"><small>Jika halaman putih/blank, itu biasanya dari Rocket Loader—sudah di-bypass otomatis.</small></p>
    </div>
  </div>
  <script data-cfasync="false">
    fetch("/healthz",{cache:"no-store"})
      .then(r=>document.getElementById("health").innerHTML=r.ok?"<p class=ok>Health: OK</p>":"<p class=bad>Health: gagal</p>")
      .catch(()=>document.getElementById("health").innerHTML="<p class=bad>Health: gagal</p>");
  </script>
</body>
</html>
EOF
  # sediakan /healthz (200 OK)
  printf "ok" >/webroot/healthz
'

# --- Salin eve.json dan buat eve.csv ---
echo ">> Ekspor eve.json -> webroot dan buat eve.csv..."
docker run --rm -v "${VOL_SURI_LOGS}:/logs:ro" -v "${VOL_WEBROOT}:/webroot" busybox sh -lc '
  [ -f /logs/eve.json ] && cp -af /logs/eve.json /webroot/eve.json || true
'
docker run --rm -v "${VOL_SURI_LOGS}:/logs:ro" -v "${VOL_WEBROOT}:/webroot" python:3.11-alpine sh -lc '
python - <<PY
import json, csv, os, sys
src="/logs/eve.json"; dst="/webroot/eve.csv"
if not os.path.exists(src): sys.exit(0)
fields=["timestamp","event_type","src_ip","src_port","dest_ip","dest_port","proto","signature","category","severity"]
with open(dst,"w",newline="",encoding="utf-8") as fcsv:
    w=csv.writer(fcsv); w.writerow(fields)
    with open(src,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: o=json.loads(line)
            except: continue
            alert = o.get("alert") or {}
            row=[o.get("timestamp",""),o.get("event_type",""),o.get("src_ip",""),o.get("src_port",""),
                 o.get("dest_ip",""),o.get("dest_port",""),o.get("proto",""),
                 alert.get("signature",""),alert.get("category",""),alert.get("severity","")]
            w.writerow(row)
print("Wrote",dst)
PY
'

# --- Reload Caddy (kalau ada perubahan di file) ---
echo ">> Reload Caddy..."
$COMPOSE exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile || true

echo "OK. Tes cepat:"
echo "  curl -I http://127.0.0.1:8080/healthz         # 200 OK"
echo "  curl -I -u fox:foxziemalam999 http://127.0.0.1:8080/"
echo "  buka http://127.0.0.1:8080/  (auth basic)"
echo "  unduh http://127.0.0.1:8080/eve.json & /eve.csv"
