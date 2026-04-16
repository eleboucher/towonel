use std::fmt;
use std::path::Path;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;
use zeroize::Zeroizing;

/// Re-export the fips204 constants so callers don't need to depend on
/// fips204 directly. `PK_LEN = 1952`, `SIG_LEN = 3309`.
pub use fips204::ml_dsa_65::{PK_LEN as PQ_PUB_KEY_LEN, SIG_LEN as PQ_SIGNATURE_LEN};

/// Seed length for ML-DSA-65 deterministic key derivation (FIPS 204 §3.6).
pub const PQ_SEED_LEN: usize = 32;

/// A tenant's public identity.
///
/// Under the hood it's just 32 bytes, defined as `SHA-256(pq_public_key)`.
/// The hex-encoded form is the canonical string representation (same shape
/// as it was in v0.1.x when the id was an Ed25519 pubkey — every existing
/// log/CLI/DB reference keeps working).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId([u8; 32]);

impl TenantId {
    /// Construct from raw bytes (no SHA-256 derivation). For round-tripping
    /// bytes already stored in the DB; derive from a pubkey via [`derive`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive `TenantId = sha256(pq_public_key)`.
    pub fn derive(pq_pubkey: &PqPublicKey) -> Self {
        let digest = sha2::Sha256::digest(pq_pubkey.as_bytes().as_slice());
        Self(digest.into())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdParseError {
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Only produced by `AgentId::from_str` — `TenantId` is a plain hash.
    #[error("invalid Ed25519 public key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
}

impl FromStr for TenantId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(bytes))
    }
}

impl Serialize for TenantId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            String::deserialize(d)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            let bytes = serde_bytes::ByteBuf::deserialize(d)?;
            let arr: [u8; 32] = bytes
                .as_ref()
                .try_into()
                .map_err(|_| serde::de::Error::custom("tenant_id must be exactly 32 bytes"))?;
            Ok(Self(arr))
        }
    }
}

/// An ML-DSA-65 public key.
///
/// Stored boxed so moves and clones don't copy 1952 bytes on the stack.
/// Cloned freely because the hub holds one per tenant and re-fetches it for
/// every `POST /v1/entries` verification.
#[derive(Clone)]
pub struct PqPublicKey(Box<[u8; PQ_PUB_KEY_LEN]>);

impl PqPublicKey {
    pub fn from_bytes(bytes: [u8; PQ_PUB_KEY_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// Attempt to construct from an arbitrary-length byte slice. Fails if
    /// the slice is not exactly [`PQ_PUB_KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PqKeyError> {
        let arr: [u8; PQ_PUB_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| PqKeyError::WrongLength(bytes.len()))?;
        Ok(Self::from_bytes(arr))
    }

    pub fn as_bytes(&self) -> &[u8; PQ_PUB_KEY_LEN] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PqKeyError {
    #[error("ml-dsa-65 public key must be exactly {PQ_PUB_KEY_LEN} bytes, got {0}")]
    WrongLength(usize),
    #[error("invalid base64url encoding: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl PartialEq for PqPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for PqPublicKey {}

impl fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short: String = B64.encode(&self.0[..8]);
        write!(f, "PqPublicKey({short}…, {} bytes)", PQ_PUB_KEY_LEN)
    }
}

impl fmt::Display for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&B64.encode(self.0.as_slice()))
    }
}

impl FromStr for PqPublicKey {
    type Err = PqKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = B64.decode(s.trim())?;
        Self::from_slice(&bytes)
    }
}

impl Serialize for PqPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(self.0.as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for PqPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            String::deserialize(d)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            let bytes = serde_bytes::ByteBuf::deserialize(d)?;
            Self::from_slice(bytes.as_ref()).map_err(serde::de::Error::custom)
        }
    }
}

/// A tenant's ML-DSA-65 signing keypair. The 32-byte seed is the only
/// state persisted on disk; `pub_key` / `priv_key` / `tenant_id` are
/// cached after derivation to keep `id()` / `public_key()` allocation-free.
///
/// Both `priv_key` (via fips204's `ZeroizeOnDrop`) and `seed` (via
/// `zeroize::Zeroizing`) are zeroed on drop.
pub struct TenantKeypair {
    seed: Zeroizing<[u8; PQ_SEED_LEN]>,
    priv_key: ml_dsa_65::PrivateKey,
    public_key: PqPublicKey,
    tenant_id: TenantId,
}

impl fmt::Debug for TenantKeypair {
    /// Prints only the public `TenantId` — never the seed or private key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantKeypair")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl TenantKeypair {
    /// Generate a fresh keypair, seeded from the OS RNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; PQ_SEED_LEN];
        getrandom::fill(&mut seed).expect("OS RNG failed");
        Self::from_seed(seed)
    }

    /// Reconstruct a keypair deterministically from its 32-byte seed.
    /// The seed is the bytes persisted in the tenant key file.
    pub fn from_seed(seed: [u8; PQ_SEED_LEN]) -> Self {
        let (pub_key, priv_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        let public_key = PqPublicKey::from_bytes(pub_key.into_bytes());
        let tenant_id = TenantId::derive(&public_key);
        Self {
            seed: Zeroizing::new(seed),
            priv_key,
            public_key,
            tenant_id,
        }
    }

    /// Seed used to derive the keypair. Same bytes as the on-disk key file.
    pub fn seed(&self) -> &[u8; PQ_SEED_LEN] {
        &self.seed
    }

    pub fn public_key(&self) -> &PqPublicKey {
        &self.public_key
    }

    pub fn id(&self) -> TenantId {
        self.tenant_id
    }

    /// Randomized ML-DSA-65 signature over `message` (FIPS 204 §3.7 with
    /// OS RNG hedged randomness). Each call produces a different signature
    /// for the same input — verify via [`verify_pq_signature`].
    pub fn sign(&self, message: &[u8]) -> [u8; PQ_SIGNATURE_LEN] {
        self.priv_key
            .try_sign(message, b"")
            .expect("ml-dsa sign should not fail with empty ctx")
    }

    /// Deterministic ML-DSA-65 signature (all-zero randomness seed).
    /// For snapshot / wire-format tests that need byte-stable signatures.
    /// **Production code must use [`sign`] (randomized).**
    #[doc(hidden)]
    pub fn sign_deterministic(&self, message: &[u8]) -> [u8; PQ_SIGNATURE_LEN] {
        self.priv_key
            .try_sign_with_seed(&[0u8; 32], message, b"")
            .expect("ml-dsa deterministic sign should not fail with empty ctx")
    }
}

/// Verify an ML-DSA-65 signature over `message` against `pq_pubkey`.
/// Returns `false` on signature mismatch, malformed pubkey bytes, or any
/// internal fips204 decode failure.
pub fn verify_pq_signature(
    pq_pubkey: &PqPublicKey,
    message: &[u8],
    signature: &[u8; PQ_SIGNATURE_LEN],
) -> bool {
    match ml_dsa_65::PublicKey::try_from_bytes(*pq_pubkey.as_bytes()) {
        Ok(pk) => pk.verify(message, signature, b""),
        Err(_) => false,
    }
}

/// An agent's public identity. Wraps an Ed25519 public key, because the
/// agent identifies itself to iroh's (classical) transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgentId(VerifyingKey);

/// Re-export iroh's EndpointId directly — it's already an Ed25519 public key.
pub type NodeId = iroh::EndpointId;

impl AgentId {
    pub fn from_key(key: VerifyingKey) -> Self {
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(bytes).map(Self)
    }

    pub fn as_key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for AgentId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(VerifyingKey::from_bytes(&bytes)?))
    }
}

impl Serialize for AgentId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for AgentId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            String::deserialize(d)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            let bytes = serde_bytes::ByteBuf::deserialize(d)?;
            let arr: [u8; 32] = bytes
                .as_ref()
                .try_into()
                .map_err(|_| serde::de::Error::custom("agent_id must be exactly 32 bytes"))?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// An agent's Ed25519 signing keypair (for iroh handshakes, not config signing).
pub struct AgentKeypair(SigningKey);

impl AgentKeypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("OS RNG failed");
        Self(SigningKey::from_bytes(&bytes))
    }

    pub fn from_signing_key(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn id(&self) -> AgentId {
        AgentId(self.0.verifying_key())
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

/// Write key bytes to a file with 0o600 permissions on Unix.
pub fn write_key_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

/// Load 32 key-file bytes, or generate fresh bytes, save them with 0o600
/// permissions, and return them. Shared by every 32-byte seed use in the
/// codebase: iroh node key, iroh agent key, ML-DSA tenant seed.
fn load_or_generate_key_bytes(path: &Path) -> anyhow::Result<[u8; 32]> {
    if path.exists() {
        std::fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("key file {} must be exactly 32 bytes", path.display()))
    } else {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("OS RNG failed");
        write_key_file(path, &bytes)?;
        Ok(bytes)
    }
}

/// Load an iroh `SecretKey` from a file, or generate and save one.
pub fn load_or_generate_secret_key(path: &Path) -> anyhow::Result<iroh::SecretKey> {
    load_or_generate_key_bytes(path).map(iroh::SecretKey::from)
}

/// Load an Ed25519 `SigningKey` from a file, or generate and save one.
/// Used by agents (iroh transport). Tenants use [`load_or_generate_tenant_keypair`].
pub fn load_or_generate_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    load_or_generate_key_bytes(path).map(|b| SigningKey::from_bytes(&b))
}

/// Load a tenant ML-DSA-65 keypair from its 32-byte seed file, or generate
/// a fresh seed and save it.
pub fn load_or_generate_tenant_keypair(path: &Path) -> anyhow::Result<TenantKeypair> {
    load_or_generate_key_bytes(path).map(TenantKeypair::from_seed)
}

/// Load an existing tenant ML-DSA-65 keypair. Errors (never generates) if
/// the file is missing — callers that want auto-generation use
/// [`load_or_generate_tenant_keypair`].
pub fn load_tenant_keypair(path: &Path) -> anyhow::Result<TenantKeypair> {
    let bytes: [u8; 32] = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read tenant key at {}: {e}", path.display()))?
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("tenant key at {} must be exactly 32 bytes", path.display())
        })?;
    Ok(TenantKeypair::from_seed(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TenantKeypair / TenantId / PqPublicKey ---

    #[test]
    fn tenant_keypair_deterministic_from_seed() {
        let seed = [42u8; PQ_SEED_LEN];
        let a = TenantKeypair::from_seed(seed);
        let b = TenantKeypair::from_seed(seed);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn tenant_keypair_generate_is_random() {
        let a = TenantKeypair::generate();
        let b = TenantKeypair::generate();
        assert_ne!(a.seed(), b.seed());
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn tenant_id_derives_from_pubkey_via_sha256() {
        let kp = TenantKeypair::from_seed([7u8; PQ_SEED_LEN]);
        let pk = kp.public_key();

        let expected = {
            let hash: [u8; 32] = sha2::Sha256::digest(pk.as_bytes().as_slice()).into();
            TenantId::from_bytes(&hash)
        };
        assert_eq!(kp.id(), expected);
        assert_eq!(TenantId::derive(pk), expected);
    }

    #[test]
    fn tenant_id_hex_roundtrip() {
        let kp = TenantKeypair::generate();
        let id = kp.id();
        let parsed: TenantId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
        assert_eq!(id.to_string().len(), 64);
    }

    #[test]
    fn tenant_id_rejects_bad_hex() {
        assert!("not-hex".parse::<TenantId>().is_err());
        assert!("abcd".parse::<TenantId>().is_err()); // too short
    }

    #[test]
    fn tenant_id_json_roundtrip() {
        let kp = TenantKeypair::generate();
        let id = kp.id();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.contains(&id.to_string()));
        let parsed: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    // --- PqPublicKey encoding ---

    #[test]
    fn pq_pubkey_base64url_roundtrip() {
        let kp = TenantKeypair::from_seed([3u8; PQ_SEED_LEN]);
        let pk = kp.public_key();
        let encoded = pk.to_string();
        // base64url of 1952 bytes without padding = 2603 chars.
        assert_eq!(encoded.len(), 2603);
        let parsed: PqPublicKey = encoded.parse().unwrap();
        assert_eq!(&parsed, pk);
    }

    #[test]
    fn pq_pubkey_accepts_trimmed_whitespace() {
        let kp = TenantKeypair::from_seed([4u8; PQ_SEED_LEN]);
        let pk = kp.public_key();
        let with_ws = format!("\n  {}  \n", pk);
        let parsed: PqPublicKey = with_ws.parse().unwrap();
        assert_eq!(&parsed, pk);
    }

    #[test]
    fn pq_pubkey_rejects_wrong_length() {
        // Empty
        assert!(PqPublicKey::from_slice(&[]).is_err());
        // One byte short
        assert!(PqPublicKey::from_slice(&vec![0u8; PQ_PUB_KEY_LEN - 1]).is_err());
        // One byte long
        assert!(PqPublicKey::from_slice(&vec![0u8; PQ_PUB_KEY_LEN + 1]).is_err());
    }

    #[test]
    fn pq_pubkey_json_roundtrip() {
        let kp = TenantKeypair::generate();
        let pk = kp.public_key();
        let json = serde_json::to_string(&pk).unwrap();
        let parsed: PqPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, &parsed);
    }

    #[test]
    fn pq_pubkey_debug_is_short_not_full_blob() {
        let kp = TenantKeypair::from_seed([5u8; PQ_SEED_LEN]);
        let dbg = format!("{:?}", kp.public_key());
        assert!(dbg.contains("bytes"));
        assert!(
            dbg.len() < 100,
            "debug output should be short, got {}",
            dbg.len()
        );
    }

    // --- Sign / verify ---

    #[test]
    fn sign_verify_round_trip() {
        let kp = TenantKeypair::from_seed([11u8; PQ_SEED_LEN]);
        let msg = b"hello turbo-tunnel";
        let sig = kp.sign(msg);
        assert!(verify_pq_signature(kp.public_key(), msg, &sig));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kp = TenantKeypair::from_seed([12u8; PQ_SEED_LEN]);
        let sig = kp.sign(b"original");
        assert!(!verify_pq_signature(kp.public_key(), b"tampered", &sig));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let alice = TenantKeypair::from_seed([13u8; PQ_SEED_LEN]);
        let bob = TenantKeypair::from_seed([14u8; PQ_SEED_LEN]);
        let msg = b"alice speaks";
        let sig = alice.sign(msg);
        // Alice's sig under Bob's pubkey must fail.
        assert!(!verify_pq_signature(bob.public_key(), msg, &sig));
    }

    #[test]
    fn sign_randomized_produces_valid_distinct_signatures() {
        let kp = TenantKeypair::from_seed([15u8; PQ_SEED_LEN]);
        let msg = b"same input different output";
        let a = kp.sign(msg);
        let b = kp.sign(msg);
        // Both must verify.
        assert!(verify_pq_signature(kp.public_key(), msg, &a));
        assert!(verify_pq_signature(kp.public_key(), msg, &b));
        // Randomized signing should produce different bytes (overwhelmingly likely).
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn sign_deterministic_is_stable() {
        let kp = TenantKeypair::from_seed([15u8; PQ_SEED_LEN]);
        let msg = b"same input same output";
        let a = kp.sign_deterministic(msg);
        let b = kp.sign_deterministic(msg);
        assert_eq!(&a[..], &b[..]);
    }

    // --- Key file helpers ---

    #[test]
    fn load_or_generate_tenant_keypair_creates_file() {
        let dir = std::env::temp_dir().join(format!("turbo-test-tkp-{}", std::process::id()));
        let path = dir.join("tenant.key");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);

        let kp1 = load_or_generate_tenant_keypair(&path).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap().len(), PQ_SEED_LEN);

        // Reloading gives the same keypair.
        let kp2 = load_or_generate_tenant_keypair(&path).unwrap();
        assert_eq!(kp1.seed(), kp2.seed());
        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.id(), kp2.id());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_generate_tenant_keypair_rejects_wrong_size() {
        let dir = std::env::temp_dir().join(format!("turbo-test-tkp-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.key");
        std::fs::write(&path, [0u8; 16]).unwrap();

        let err = load_or_generate_tenant_keypair(&path).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Agent identity (unchanged) ---

    #[test]
    fn agent_keypair_hex_roundtrip() {
        let kp = AgentKeypair::generate();
        let id = kp.id();
        let parsed: AgentId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    // --- Secret key helpers ---

    #[test]
    fn load_or_generate_secret_key_roundtrips() {
        let dir = std::env::temp_dir().join(format!("turbo-test-sk-{}", std::process::id()));
        let path = dir.join("secret.key");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);

        let k1 = load_or_generate_secret_key(&path).unwrap();
        let k2 = load_or_generate_secret_key(&path).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
