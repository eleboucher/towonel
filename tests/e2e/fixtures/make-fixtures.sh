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

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 3650 \
  -nodes \
  -keyout hub-tls.key \
  -out hub-tls.pem \
  -subj "/CN=hub-node" \
  -addext "subjectAltName=DNS:hub-node,IP:127.0.0.1"

# Pebble (local ACME CA) fixtures. pebble-ca.pem signs the cert Pebble's ACME
# directory listener presents on :14000; the hub trusts it via SSL_CERT_FILE.
# The listener cert's SAN must be `pebble` (the compose service name).
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 3650 \
  -nodes \
  -keyout pebble-ca.key \
  -out pebble-ca.pem \
  -subj "/CN=towonel-e2e-pebble-ca"

openssl req \
  -newkey rsa:2048 \
  -sha256 \
  -nodes \
  -keyout pebble.key \
  -out pebble.csr \
  -subj "/CN=pebble"

openssl x509 \
  -req \
  -in pebble.csr \
  -CA pebble-ca.pem \
  -CAkey pebble-ca.key \
  -CAcreateserial \
  -days 3650 \
  -out pebble.pem \
  -extfile <(printf "subjectAltName=DNS:pebble,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

rm -f pebble.csr pebble-ca.srl
