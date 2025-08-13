#!/usr/bin/env bash
set -euo pipefail
IFACE="${SURI_IFACE:-wlan0}"

# Matikan GRO/LRO (wifi mungkin abaikan; tetap safe)
ethtool -K "$IFACE" gro off || true
ethtool -K "$IFACE" lro off || true

# Rules minimal
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update enable-source et/open abuse.ch/urlhaus || true
  for c in $(suricata-update list-categories | awk '{print $1}'); do
    case " $c " in
      *" scan "*|*" web-attack "*|*" web-php "*|*" sql "*|*" exploit "*|*" brute-force "*|*" dns "*|*" http "*|*" tls "*)
        suricata-update enable-category "$c" >/dev/null 2>&1 || true;;
      *)  suricata-update disable-category "$c" >/dev/null 2>&1 || true;;
    esac
  done
  suricata-update || true
fi

# Test & run
suricata -T -c /etc/suricata/suricata.yaml || { echo "[ERR] config invalid"; exit 1; }
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --runmode=autofp -D
