#!/usr/bin/env bash
# Install ddns-cf on Debian / Ubuntu as a systemd service that starts on boot.
set -euo pipefail

APP=ddns-cf
DIR=/opt/ddns-cf
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Please run as root: sudo $0"; exit 1; }
[[ -f /etc/debian_version ]] || echo "WARN: not a Debian/Ubuntu system, continuing anyway"

echo "==> Checking dependencies"
need=()
command -v python3 >/dev/null || need+=(python3)
command -v ping    >/dev/null || need+=(iputils-ping)
command -v ip      >/dev/null || need+=(iproute2)
if ((${#need[@]})); then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' \
  || { echo "Python 3.8+ required"; exit 1; }

echo "==> Installing files to $DIR"
install -d -m 755 "$DIR"
install -m 755 "$SRC/ddns_cf.py"      "$DIR/ddns_cf.py"
install -m 644 "$SRC/.env.example"    "$DIR/.env.example"
[[ -f "$SRC/README.md" ]] && install -m 644 "$SRC/README.md" "$DIR/README.md"
ln -sf "$DIR/ddns_cf.py" /usr/local/bin/ddns-cf

if [[ -f "$DIR/.env" ]]; then
  echo "    keeping existing $DIR/.env"
elif [[ -f "$SRC/.env" ]]; then
  install -m 600 "$SRC/.env" "$DIR/.env"
  echo "    copied .env from $SRC"
else
  install -m 600 "$SRC/.env.example" "$DIR/.env"
  echo "    created $DIR/.env from template — EDIT IT before starting"
fi
chown root:root "$DIR/.env"; chmod 600 "$DIR/.env"

echo "==> Installing systemd unit"
install -m 644 "$SRC/ddns-cf.service" /etc/systemd/system/$APP.service
systemctl daemon-reload
systemctl enable $APP.service >/dev/null
echo "    enabled on boot"

if grep -qE '^CF_API_TOKEN=(your_|$)|^CF_RECORDS=.*example\.com' "$DIR/.env"; then
  echo
  echo "!! $DIR/.env still has placeholder values. Edit it, then run:"
  echo "   ddns-cf check && systemctl restart $APP"
  exit 0
fi

systemctl restart $APP.service
sleep 2
systemctl --no-pager --lines=10 status $APP.service || true
echo
echo "Done.  Logs: journalctl -u $APP -f    Test: ddns-cf check"
