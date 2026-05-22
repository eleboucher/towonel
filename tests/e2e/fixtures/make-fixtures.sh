#!/usr/bin/env bash
# Regenerates the self-signed cert the origin presents on :9443. The
# tls_passthrough case reads origin-tls.pem at runtime, so rotating the
# cert here is safe.

set -euo pipefail

cd "$(dirname "$0")"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 3650 \
  -nodes \
  -keyout origin-tls.key \
  -out origin-tls.pem \
  -subj "/CN=app.e2e.local" \
  -addext "subjectAltName=DNS:app.e2e.local,DNS:*.e2e.local"
