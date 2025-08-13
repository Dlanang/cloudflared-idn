#!/usr/bin/env bash
set -euo pipefail

IFACE="${SURI_IFACE:-wlan0}"

# Permission supaya container lain bisa baca log
umask 0022
mkdir -p /var/log/suricata
chmod -R a+rX /var/log/suricata

# Matikan GRO/LRO (kalau iface mendukung), biar capture akurat
ethtool -K "$IFACE" gro off || true
ethtool -K "$IFACE" lro off || true

# Update rules basic (opsional tapi useful)
if command -v suricata-update >/dev/null 2>&1; then
  suricata-update enable-source et/open abuse.ch/urlhaus || true
  # Minimal update; jangan agresif disable kategori kalau belum perlu
  suricata-update || true
fi

# Validasi config (fail fast)
suricata -T -c /etc/suricata/suricata.yaml

# Jalanin Suricata (daemon)
exec suricata -c /etc/suricata/suricata.yaml -i "$IFACE" -D
