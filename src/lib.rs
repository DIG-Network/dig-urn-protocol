//! # dig-urn-protocol
//!
//! The **canonical DIG content-addressing + server-untrusted verification contract** — the one
//! definition of how a DIG URN names content and how a blind client turns opaque gateway bytes into
//! verified plaintext, fail-closed.
//!
//! This crate OWNS (and is the single source of truth for):
//!
//! * **The `urn:dig:` scheme + byte-level grammar** — [`DigUrn`] parsing, [`DigUrn::canonical`]
//!   rendering, and `retrieval_key = SHA-256(canonical())` (plus the root-independent
//!   `content_key = SHA-256(canonical_rootless())`) derivation. The [`grammar`]
//!   module carries the normative ABNF, pinned by the frozen conformance vectors.
//! * **The resolution INTERFACE** — the [`UrnResolver`] trait plus [`ResolveOutcome`] /
//!   [`ResolveError`] / [`ResolveOptions`]. The contract, not the transport.
//! * **The browser content-VERIFICATION contract** — [`verify`]: rootless rejection, leaf-binding,
//!   path-fold, root-anchoring, gate-then-decrypt, and the u64-bounded chunk split — over crypto
//!   primitives INJECTED via [`verify::ContentCrypto`].
//!
//! ## A leaf crate that reimplements no crypto
//!
//! `dig-urn-protocol` has NO `dig-*` dependencies and NO transport (reqwest/tokio). The merkle-fold
//! and AES primitives are supplied by the caller (`digstore_core`), so this crate can never skew from
//! the canonical read-crypto. It performs only SHA-256 (the retrieval key + the content leaf), which
//! is byte-identical to `digstore_core`'s.
//!
//! ## Relationship to `dig-rpc-protocol`
//!
//! This crate owns addressing + resolution + verification only. It CONSUMES the `dig-rpc-protocol`
//! `PublicRead` contract conceptually for the actual fetch, but does not depend on it or duplicate
//! any RPC method — a concrete [`UrnResolver`] wires the two together.

#![forbid(unsafe_code)]

pub mod bytes;
pub mod grammar;
pub mod resolve;
pub mod urn;
pub mod verify;

pub use bytes::{Bytes32, InvalidBytes32};
pub use grammar::{CANONICAL_CHAIN, DEFAULT_RESOURCE_KEY, SALT_QUERY_MARKER, URN_ABNF, URN_PREFIX};
pub use resolve::{
    ResolveError, ResolveOptions, ResolveOutcome, ResolvedData, Result, UrnResolver,
};
pub use urn::{DigUrn, SecretSalt, UrnParseError};
pub use verify::{
    chunk_ranges, decrypt, require_blind_root, resource_leaf, verify_and_decrypt, verify_inclusion,
    ContentCrypto, FoldedProof,
};

/// The crate version (matches `Cargo.toml`), for compatibility checks.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_reported() {
        assert!(!super::version().is_empty());
    }
}
