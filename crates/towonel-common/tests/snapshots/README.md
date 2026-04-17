# Protocol snapshots

Binary test-vector fixtures for towonel protocol v1. Each file is
generated deterministically from a fixed seed/payload (see
`../snapshots_test.rs`). Re-running the test with `UPDATE_SNAPSHOTS=1`
regenerates the fixtures; plain `cargo test` verifies byte-for-byte
equality against them.

The point: catch "our dep changed its encoding subtly" regressions early,
and give a would-be second implementation something concrete to diff
against.

## Fixtures

- `tenant_seed.bin` — `[42u8; 32]`, used as the ML-DSA-65 keygen seed.
- `pq_public_key.bin` — ML-DSA-65 public key derived from that seed.
  1952 bytes.
- `tenant_id.bin` — `sha256(pq_public_key)`. 32 bytes.
- `config_payload.cbor` — canonical CBOR of a `ConfigPayload` with
  `version=1, sequence=1, timestamp=1700000000000,
   op=UpsertHostname("app.example.eu")` and the tenant id above.
  Key order `op, version, sequence, tenant_id, timestamp` per
  RFC 8949 §4.2.1 (`docs/protocol.md` §3.4).
- `signed_entry.cbor` — CBOR of a `SignedConfigEntry` wrapping that
  payload and a deterministic ML-DSA-65 signature. 3-field map
  (`payload, signature, tenant_id`).
- `tunnel_header.bin` — `write_hostname_header("app.example.eu")`
  output: two big-endian length bytes followed by the ASCII hostname.
