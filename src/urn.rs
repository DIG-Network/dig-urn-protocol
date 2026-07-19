//! [`DigUrn`] — the parsed `urn:dig:` scheme, its canonical form, and retrieval-key derivation.
//!
//! This is the source-of-truth implementation the [`crate::grammar`] ABNF describes; the frozen
//! conformance vectors (`tests/fixtures/urn_conformance.json`) prove the two agree.
//!
//! Format: `urn:dig:<chain>:<store-id>[:<root-hash>][/<resource>][?salt=<hex>]`
//! - `retrieval_key = SHA-256(canonical())` (URN identity; pins the root)
//! - `content_key   = SHA-256(canonical_rootless())` (root-independent fetch/AES-seed key)

use crate::bytes::Bytes32;
use crate::grammar::{DEFAULT_RESOURCE_KEY, SALT_QUERY_MARKER, URN_PREFIX};
use sha2::{Digest, Sha256};

/// SHA-256 of `data` as a [`Bytes32`].
fn sha256_hex(data: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Bytes32(hasher.finalize().into())
}

/// A private-store secret salt: 32 bytes of out-of-band key material.
///
/// NOT part of the URN identity (see [`crate::grammar`]) — it is a separate input to key derivation
/// so the host, which sees only the retrieval key, cannot distinguish a private store from a public
/// one. A surfaced salt MUST be exactly 32 bytes / 64 lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretSalt(pub [u8; 32]);

impl core::fmt::Debug for SecretSalt {
    /// Never render the salt bytes — it is key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretSalt(<redacted>)")
    }
}

/// A parsed DIG URN.
///
/// The `resource_key` distinguishes three states: `None` (absent — a bare store/root URN),
/// `Some("")` (a trailing slash), and `Some("path")` (a concrete resource). All three are valid;
/// [`DigUrn::effective_resource_key`] maps the first two to the [`DEFAULT_RESOURCE_KEY`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigUrn {
    /// The chain label. Canonical value is `chia`; `mainnet`/`testnet` are accepted for back-compat.
    pub chain: String,
    /// The CHIP-0035 singleton launcher id (store identity).
    pub store_id: Bytes32,
    /// The pinned on-chain generation root. `None` = the root-independent form. The root is the
    /// trust anchor for inclusion verification ONLY; it is never a key input.
    pub root_hash: Option<Bytes32>,
    /// The resource path within the store, verbatim after the FIRST `/`. See the struct docs for the
    /// three-state distinction.
    pub resource_key: Option<String>,
}

/// A parse failure with a stable, human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid DIG URN: {0}")]
pub struct UrnParseError(pub String);

impl DigUrn {
    /// Parse a canonical URN string (no `?salt=` handling — use [`DigUrn::parse_with_salt`] to peel a
    /// salt suffix first). Accepts an omitted root-hash and/or resource.
    pub fn parse(input: &str) -> Result<DigUrn, UrnParseError> {
        let rest = input
            .strip_prefix(URN_PREFIX)
            .ok_or_else(|| UrnParseError(format!("missing '{URN_PREFIX}' prefix")))?;

        // Split off the optional resource path at the FIRST '/'.
        let (head, resource_key) = match rest.split_once('/') {
            Some((h, r)) => (h, Some(r.to_string())),
            None => (rest, None),
        };

        // head = <chain>:<store-id>[:<root-hash>]
        let mut parts = head.split(':');
        let chain = parts
            .next()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| UrnParseError("missing chain".into()))?
            .to_string();
        let store_id_hex = parts
            .next()
            .ok_or_else(|| UrnParseError("missing store id".into()))?;
        let store_id = Bytes32::from_hex(store_id_hex)
            .map_err(|_| UrnParseError("store id must be 64 hex chars".into()))?;
        let root_hash = match parts.next() {
            Some(rh) => Some(
                Bytes32::from_hex(rh)
                    .map_err(|_| UrnParseError("root hash must be 64 hex chars".into()))?,
            ),
            None => None,
        };
        if parts.next().is_some() {
            return Err(UrnParseError("too many ':' segments".into()));
        }

        Ok(DigUrn {
            chain,
            store_id,
            root_hash,
            resource_key,
        })
    }

    /// Parse a URN, peeling an OPTIONAL `?salt=<hex>` suffix off the tail first.
    ///
    /// The salt is validated as non-empty hex (case-insensitive, normalised to lowercase) and
    /// returned separately; the remainder is parsed by [`DigUrn::parse`]. A conforming validator that
    /// surfaces the salt MUST require exactly 64 hex chars — this function accepts any non-empty hex
    /// and leaves the 32-byte enforcement to [`DigUrn::salt_bytes`].
    pub fn parse_with_salt(input: &str) -> Result<(DigUrn, Option<String>), UrnParseError> {
        let trimmed = input.trim();
        let (core_part, salt) = match trimmed.rsplit_once(SALT_QUERY_MARKER) {
            Some((head, salt_hex)) => {
                let salt_hex = salt_hex.trim();
                if salt_hex.is_empty() || !salt_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(UrnParseError(format!(
                        "{SALT_QUERY_MARKER} must be non-empty hex"
                    )));
                }
                (head, Some(salt_hex.to_ascii_lowercase()))
            }
            None => (trimmed, None),
        };
        Ok((DigUrn::parse(core_part)?, salt))
    }

    /// Validate a peeled salt hex string into a [`SecretSalt`] — exactly 32 bytes / 64 hex.
    pub fn salt_bytes(salt_hex: &str) -> Result<SecretSalt, UrnParseError> {
        Bytes32::from_hex(salt_hex.trim())
            .map(|b| SecretSalt(b.0))
            .map_err(|_| UrnParseError("secret salt must be 64 hex chars".into()))
    }

    /// Render the canonical URN string.
    pub fn canonical(&self) -> String {
        let mut s = format!("{URN_PREFIX}{}:{}", self.chain, self.store_id.to_hex());
        if let Some(rh) = &self.root_hash {
            s.push(':');
            s.push_str(&rh.to_hex());
        }
        if let Some(rk) = &self.resource_key {
            s.push('/');
            s.push_str(rk);
        }
        s
    }

    /// The resource path, defaulting an absent or empty key to [`DEFAULT_RESOURCE_KEY`].
    pub fn effective_resource_key(&self) -> &str {
        match self.resource_key.as_deref() {
            Some(k) if !k.is_empty() => k,
            _ => DEFAULT_RESOURCE_KEY,
        }
    }

    /// The canonical ROOT-INDEPENDENT resource URN. Dropping the root keeps the retrieval and
    /// decryption keys stable across generations (matching the host/CLI commit-time derivation), and
    /// carries the [`DigUrn::effective_resource_key`] (empty/absent → `index.html`).
    pub fn canonical_rootless(&self) -> DigUrn {
        DigUrn {
            chain: self.chain.clone(),
            store_id: self.store_id,
            root_hash: None,
            resource_key: Some(self.effective_resource_key().to_string()),
        }
    }

    /// The URN-identity retrieval key: `SHA-256(canonical())` — over the FULL canonical form
    /// (including the pinned root, if any). This is the value the frozen conformance corpus pins and
    /// that `digstore_core::Urn::retrieval_key` derives; it is a property of the URN string.
    pub fn retrieval_key(&self) -> Bytes32 {
        sha256_hex(self.canonical().as_bytes())
    }

    /// `retrieval_key` as lowercase hex.
    pub fn retrieval_key_hex(&self) -> String {
        self.retrieval_key().to_hex()
    }

    /// The ROOT-INDEPENDENT content key: `SHA-256(canonical_rootless())`. Stable across generations,
    /// it is the identifier a resolver uses to FETCH content and the seed for the AES key derivation
    /// (matching the host/CLI commit-time derivation) — distinct from [`DigUrn::retrieval_key`],
    /// which pins the root.
    pub fn content_key(&self) -> Bytes32 {
        sha256_hex(self.canonical_rootless().canonical().as_bytes())
    }

    /// `content_key` as lowercase hex.
    pub fn content_key_hex(&self) -> String {
        self.content_key().to_hex()
    }

    /// The store id as lowercase hex.
    pub fn store_id_hex(&self) -> String {
        self.store_id.to_hex()
    }

    /// The pinned generation root as lowercase hex, if the URN carries one.
    pub fn root_hex(&self) -> Option<String> {
        self.root_hash.map(|r| r.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> String {
        "11".repeat(32)
    }

    #[test]
    fn parses_full_form_and_canonicalises_idempotently() {
        let input = format!("urn:dig:chia:{}:{}/index.html", store(), "22".repeat(32));
        let urn = DigUrn::parse(&input).unwrap();
        assert_eq!(urn.chain, "chia");
        assert_eq!(urn.root_hash.unwrap().to_hex(), "22".repeat(32));
        assert_eq!(urn.resource_key.as_deref(), Some("index.html"));
        assert_eq!(urn.canonical(), input);
    }

    #[test]
    fn bare_store_has_no_resource_and_defaults_to_index() {
        let urn = DigUrn::parse(&format!("urn:dig:chia:{}", store())).unwrap();
        assert_eq!(urn.resource_key, None);
        assert_eq!(urn.effective_resource_key(), "index.html");
    }

    #[test]
    fn trailing_slash_is_empty_resource_distinct_from_absent() {
        let urn = DigUrn::parse(&format!("urn:dig:chia:{}/", store())).unwrap();
        assert_eq!(urn.resource_key.as_deref(), Some(""));
        assert_eq!(urn.effective_resource_key(), "index.html");
    }

    #[test]
    fn resource_split_is_at_first_slash() {
        let urn = DigUrn::parse(&format!("urn:dig:chia:{}/a/b/c.json", store())).unwrap();
        assert_eq!(urn.resource_key.as_deref(), Some("a/b/c.json"));
    }

    #[test]
    fn retrieval_key_pins_the_root_but_content_key_is_root_independent() {
        let rootless = DigUrn::parse(&format!("urn:dig:chia:{}/a", store())).unwrap();
        let rooted =
            DigUrn::parse(&format!("urn:dig:chia:{}:{}/a", store(), "22".repeat(32))).unwrap();
        // retrieval_key = SHA-256(canonical) DIFFERS once a root is pinned (frozen-corpus rule)...
        assert_ne!(rootless.retrieval_key(), rooted.retrieval_key());
        // ...while content_key = SHA-256(canonical_rootless) stays stable across generations.
        assert_eq!(rootless.content_key(), rooted.content_key());
    }

    #[test]
    fn accepts_mainnet_and_testnet_labels_for_backcompat() {
        assert!(DigUrn::parse(&format!("urn:dig:mainnet:{}/a", store())).is_ok());
        assert!(DigUrn::parse(&format!("urn:dig:testnet:{}", store())).is_ok());
    }

    #[test]
    fn rejects_bad_forms() {
        assert!(DigUrn::parse("urn:other:chia:00").is_err());
        assert!(DigUrn::parse("not-a-urn").is_err());
        assert!(DigUrn::parse("urn:dig:chia").is_err());
        assert!(DigUrn::parse(&format!("urn:dig::{}", store())).is_err());
        assert!(DigUrn::parse("urn:dig:chia:zzzz").is_err());
        assert!(DigUrn::parse(&format!(
            "urn:dig:chia:{}:{}:{}",
            store(),
            "22".repeat(32),
            "33".repeat(32)
        ))
        .is_err());
    }

    #[test]
    fn peels_salt_suffix_and_leaves_it_out_of_identity() {
        let with_salt = format!("urn:dig:chia:{}/index.html?salt=DEADBEEF", store());
        let (urn, salt) = DigUrn::parse_with_salt(&with_salt).unwrap();
        assert_eq!(salt.as_deref(), Some("deadbeef")); // normalised lowercase
        assert_eq!(urn.resource_key.as_deref(), Some("index.html"));
    }

    #[test]
    fn core_parser_leaves_salt_query_inside_resource() {
        // Without peeling, the ?salt suffix is part of the resource (frozen-corpus rule).
        let urn = DigUrn::parse(&format!(
            "urn:dig:chia:{}/index.html?salt=deadbeef",
            store()
        ))
        .unwrap();
        assert_eq!(
            urn.resource_key.as_deref(),
            Some("index.html?salt=deadbeef")
        );
    }

    #[test]
    fn salt_bytes_requires_64_hex() {
        assert!(DigUrn::salt_bytes(&"ab".repeat(32)).is_ok());
        assert!(DigUrn::salt_bytes("deadbeef").is_err());
    }

    #[test]
    fn empty_salt_query_rejected() {
        assert!(DigUrn::parse_with_salt(&format!("urn:dig:chia:{}/a?salt=", store())).is_err());
    }
}
