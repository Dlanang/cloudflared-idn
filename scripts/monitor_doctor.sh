#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-}"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$ROOT_DIR/docker-compose.yml"
CADDYDIR="$ROOT_DIR/caddy"

red(){ printf "\033[31m%s\033[0m\n" "$*"; }
grn(){ printf "\033[32m%s\033[0m\n" "$*"; }
ylw(){ printf "\033[33m%s\033[0m\n" "$*"; }
blu(){ printf "\033[34m%s\033[0m\n" "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { red "butuh '$1'"; exit 1; }; }

dig_q(){ dig +short "$@" 2>/dev/null || true; }

is_cf_ip() {
  local ip="$1"
  [[ "$ip" =~ ^104\.16\.|^104\.17\.|^104\.18\.|^104\.19\.|^104\.20\.|^104\.21\.|^104\.22\.|^104\.23\.|^104\.24\.|^104\.25\.|^104\.26\.|^172\.64\.|^172\.65\.|^172\.66\.|^172\.67\.|^188\.114\.|^2606:4700: ]] && return 0 || return 1
}

# 1) Pastikan stack up & landing public, /monitor protected
blu ">> Up stack & publish frontend…"
docker compose -f "$COMPOSE" up -d
docker compose -f "$COMPOSE" exec -T frontend-builder sh -lc 'npm run build >/dev/null 2>&1 || npm run build; rm -rf /webroot/* && cp -r dist/* /webroot/'

# Pastikan Caddyfile pakai basic_auth (bukan basicauth)
if grep -qE '\bbasicauth\b' "$CADDYDIR/Caddyfile"; then
  ylw ">> Ganti basicauth -> basic_auth"
  sed -i 's/\bbasicauth\b/basic_auth/g' "$CADDYDIR/Caddyfile"
fi

# Reload Caddy
blu ">> Reload Caddy…"
docker compose -f "$COMPOSE" exec -T caddy-rev caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null || true
docker compose -f "$COMPOSE" exec -T caddy-rev caddy reload --config /etc/caddy/Caddyfile >/dev/null || true

# 2) Self test origin
blu ">> Self-test origin (localhost:8080)"
O1=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz || true)
O2=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ || true)
O3=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/monitor || true)
O4=$(curl -s -o /dev/null -u fox:foxziemalam999 -w '%{http_code}' -L http://127.0.0.1:8080/monitor -o /dev/null || true)
echo " /healthz : $O1  (harus 200)"
echo " /        : $O2  (harus 200)"
echo " /monitor : $O3  (harus 401)"
echo " /monitor(auth,-L) : $O4 (harus 200)"

if [[ "$O1$O2$O3" != "200200401" ]]; then
  red "Origin belum sesuai. Cek Caddyfile & restart Caddy container."
  docker compose -f "$COMPOSE" restart caddy-rev
  sleep 2
fi

# 3) Test dari cloudflared container ke origin
blu ">> Test dari dalam container cloudflared -> http://localhost:8080/healthz"
docker compose -f "$COMPOSE" exec -T cloudflared sh -lc 'apk add --no-cache curl >/dev/null 2>&1 || true; curl -sS -I http://localhost:8080/healthz || true' || true

# 4) Diagnosa Cloudflare (kalau domain diberikan)
if [[ -n "$DOMAIN" ]]; then
  blu ">> Diagnosa DNS/Cloudflare untuk: $DOMAIN"
  need dig || true

  ZONE="$(printf "%s\n" "$DOMAIN" | awk -F. '{n=NF; print $(n-1)"."$n}')"
  NS=$(dig_q NS "$ZONE")
  CNAME=$(dig_q CNAME "$DOMAIN")
  Arec=$(dig_q A "$DOMAIN")
  AAAArec=$(dig_q AAAA "$DOMAIN")

  echo " NS($ZONE):"
  echo "$NS" | sed 's/^/   - /'
  echo " CNAME($DOMAIN): ${CNAME:-<none>}"
  echo " A($DOMAIN):"
  echo "${Arec:-<none>}" | sed 's/^/   - /'
  echo " AAAA($DOMAIN):"
  echo "${AAAArec:-<none>}" | sed 's/^/   - /'

  # indikasi zone belum di Cloudflare
  if ! echo "$NS" | grep -qi 'cloudflare\.com'; then
    red ">> Nameserver zona tampaknya BUKAN Cloudflare."
    echo "   - Pindahkan nameserver domain ke Cloudflare (di registrar) agar DNS record public hostname dibuat/di-serve oleh Cloudflare."
  fi

  # cek apakah resolve ke Anycast CF
  CF_OK=0
  for ip in $Arec $AAAArec; do
    if is_cf_ip "$ip"; then CF_OK=1; fi
  done

  if [[ "$CF_OK" -eq 0 ]]; then
    red ">> $DOMAIN tidak mengarah ke edge Cloudflare."
    echo "   FIX:"
    echo "   1) Di Zero Trust > Access > Tunnels > (tunnel kamu) > Public hostnames:"
    echo "      - Hostname: $DOMAIN, Path: *, Service: http://localhost:8080"
    echo "   2) Pastikan di DNS Zone Cloudflare ada CNAME 'infra' (atau host yang dipakai) -> <UUID>.cfargotunnel.com (PROXIED/orange)."
    echo "   3) Tunggu propagasi DNS (1-5 menit), lalu tes lagi:"
    echo "      curl -I https://$DOMAIN/healthz"
    echo "      curl -I -L -u fox:foxziemalam999 https://$DOMAIN/monitor"
  else
    grn ">> $DOMAIN sudah resolve ke edge Cloudflare."
    echo "Tes HTTP via Cloudflare:"
    curl -s -o /dev/null -w "  /healthz : %{http_code}\n" "https://$DOMAIN/healthz" || true
    curl -s -o /dev/null -w "  /monitor(auth) : %{http_code}\n" -L -u fox:foxziemalam999 "https://$DOMAIN/monitor" || true
  fi
else
  ylw ">> Lewati tes Cloudflare (tidak ada domain arg). Contoh: sudo ./monitor_doctor.sh infra.dhimaslanangnugroho.my.id"
fi

grn ">> Done."
