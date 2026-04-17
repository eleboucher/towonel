#![allow(clippy::manual_assert, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use towonel_common::config_entry::{ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::{TenantId, TenantKeypair};
use towonel_common::tunnel::write_hostname_header;

/// Fixed test-vector seed. Changing this is a breaking change to the
/// fixtures — use `UPDATE_SNAPSHOTS=1` to regenerate.
const TENANT_SEED: [u8; 32] = [42u8; 32];
const FIXED_HOSTNAME: &str = "app.example.eu";
const FIXED_SEQUENCE: u64 = 1;
const FIXED_TIMESTAMP_MS: u64 = 1_700_000_000_000;

fn snapshots_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
}

/// Read a fixture file, or panic with a helpful message if missing.
fn read_fixture(name: &str) -> Vec<u8> {
    let path = snapshots_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "snapshot {name}: read failed ({e}). If this is a new fixture, \
             run with UPDATE_SNAPSHOTS=1 to generate it."
        )
    })
}

/// Either assert equality with the on-disk fixture, or overwrite it when
/// `UPDATE_SNAPSHOTS` is set.
fn assert_or_update(name: &str, actual: &[u8]) {
    let path = snapshots_dir().join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        eprintln!(
            "snapshot {name}: wrote {} bytes to {}",
            actual.len(),
            path.display()
        );
        return;
    }
    let expected = read_fixture(name);
    if expected != actual {
        panic!(
            "snapshot {name} mismatch. Expected {} bytes, got {}. \
             Run with UPDATE_SNAPSHOTS=1 to regenerate (after verifying the change is intentional).",
            expected.len(),
            actual.len(),
        );
    }
}

fn keypair() -> TenantKeypair {
    TenantKeypair::from_seed(TENANT_SEED)
}

fn fixed_payload(tenant_id: TenantId) -> ConfigPayload {
    ConfigPayload {
        version: 1,
        tenant_id,
        sequence: FIXED_SEQUENCE,
        timestamp: FIXED_TIMESTAMP_MS,
        op: ConfigOp::UpsertHostname {
            hostname: FIXED_HOSTNAME.to_string(),
        },
    }
}

#[test]
fn tenant_seed_fixture() {
    assert_or_update("tenant_seed.bin", &TENANT_SEED);
}

#[test]
fn pq_public_key_fixture() {
    let kp = keypair();
    assert_or_update("pq_public_key.bin", kp.public_key().as_bytes());
}

#[test]
fn tenant_id_fixture() {
    let kp = keypair();
    assert_or_update("tenant_id.bin", kp.id().as_bytes());
}

#[test]
fn config_payload_canonical_cbor_fixture() {
    let kp = keypair();
    let payload = fixed_payload(kp.id());
    // Deterministic sign so the payload_cbor is always the same.
    let entry = SignedConfigEntry::sign_deterministic(&payload, &kp).unwrap();
    assert_or_update("config_payload.cbor", &entry.payload_cbor);
}

#[test]
fn signed_entry_cbor_fixture() {
    let kp = keypair();
    let payload = fixed_payload(kp.id());
    // Deterministic sign so the fixture stays byte-stable across runs.
    let entry = SignedConfigEntry::sign_deterministic(&payload, &kp).unwrap();

    let mut buf = Vec::new();
    ciborium::into_writer(&entry, &mut buf).unwrap();
    assert_or_update("signed_entry.cbor", &buf);
}

#[tokio::test]
async fn tunnel_header_fixture() {
    let mut buf = Vec::new();
    write_hostname_header(&mut buf, FIXED_HOSTNAME)
        .await
        .unwrap();
    assert_or_update("tunnel_header.bin", &buf);
}

/// End-to-end check: the on-disk fixtures decode and verify against each
/// other. Catches the case where individual files drifted independently.
#[test]
fn fixtures_round_trip() {
    let kp = keypair();

    let pub_key = read_fixture("pq_public_key.bin");
    assert_eq!(pub_key, kp.public_key().as_bytes().as_slice());

    let tid = read_fixture("tenant_id.bin");
    assert_eq!(tid, kp.id().as_bytes().as_slice());

    let entry_bytes = read_fixture("signed_entry.cbor");
    let entry: SignedConfigEntry = ciborium::from_reader(entry_bytes.as_slice())
        .expect("signed_entry.cbor is a valid SignedConfigEntry");
    let verified = entry
        .verify(kp.public_key())
        .expect("fixture signature verifies against the fixed-seed pubkey");
    assert_eq!(verified, fixed_payload(kp.id()));
}
