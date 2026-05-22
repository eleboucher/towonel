#!/bin/sh
set -eu

BROKER_URL="${BROKER_URL:-http://test-runner:7777/token}"
MAX_WAIT_SECS="${BROKER_MAX_WAIT_SECS:-60}"

waited=0
while :; do
    token=$(curl --fail --silent --max-time 2 "$BROKER_URL" 2>/dev/null || true)
    if [ -n "$token" ]; then
        break
    fi
    waited=$((waited + 1))
    if [ "$waited" -ge "$MAX_WAIT_SECS" ]; then
        echo "agent-entrypoint: no token from $BROKER_URL after ${MAX_WAIT_SECS}s" >&2
        exit 1
    fi
    sleep 1
done

export TOWONEL_INVITE_TOKEN="$token"
exec /usr/local/bin/towonel-agent
