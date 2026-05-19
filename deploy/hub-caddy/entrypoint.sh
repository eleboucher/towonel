#!/bin/bash
# Run caddy + towonel side-by-side; exit (and let docker restart) if either dies.
set -euo pipefail

caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!

/usr/local/bin/towonel &
TOWONEL_PID=$!

shutdown() {
	kill -TERM "$CADDY_PID" "$TOWONEL_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap shutdown EXIT INT TERM

# wait -n returns when any single child exits; propagate that exit code so
# docker's restart policy can decide what to do.
wait -n
exit $?
