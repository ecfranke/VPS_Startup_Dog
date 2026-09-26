#!/usr/bin/env bash
# Remove the ddns-cf service. Keeps /opt/ddns-cf/.env unless --purge is given.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Please run as root: sudo $0"; exit 1; }

systemctl disable --now ddns-cf.service 2>/dev/null || true
rm -f /etc/systemd/system/ddns-cf.service /usr/local/bin/ddns-cf
systemctl daemon-reload

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /opt/ddns-cf
  echo "Removed service and /opt/ddns-cf"
else
  rm -f /opt/ddns-cf/ddns_cf.py /opt/ddns-cf/.env.example /opt/ddns-cf/README.md
  echo "Removed service. Kept /opt/ddns-cf/.env (use --purge to delete it)"
fi
