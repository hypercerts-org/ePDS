#!/bin/sh
set -eu

if [ -s /ca/root.crt ]; then
  if [ "$(id -u)" -eq 0 ]; then
    install -m 0644 /ca/root.crt /usr/local/share/ca-certificates/epds-e2e-root.crt
    update-ca-certificates >/dev/null
  fi
  mkdir -p "$HOME/.pki/nssdb"
  certutil -N --empty-password -d "sql:$HOME/.pki/nssdb" 2>/dev/null || true
  certutil -A -d "sql:$HOME/.pki/nssdb" -t 'C,,' \
    -n epds-e2e-root -i /ca/root.crt
fi

exec "$@"
