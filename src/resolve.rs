//! The resolution INTERFACE — the [`UrnResolver`] trait and its typed outcomes/errors.
//!
//! This crate defines the CONTRACT, not the transport: a concrete resolver (in `dig-urn-resolver`,
//! the node, the browser host) implements [`UrnResolver`] over its own I/O, while this module fixes
//! the shape every implementation shares — the three exhaustive outcomes and the catalogued error
//! taxonomy — so consumers can depend on one stable interface.
//!
//! # Three outcomes, deliberately kept distinct
//!
//! * [`ResolveOutcome::Success`] — verified, decrypted content.
//! * [`ResolveOutcome::IntegrityFailure`] — bytes WERE fetched but failed merkle/decrypt
//!   verification (tampered / decoy / wrong root). A hard, fail-CLOSED security outcome; the
//!   unverified bytes are NEVER carried here.
//! * [`ResolveOutcome::Unreachable`] — every transport tier was down; nothing was fetched. A
//!   friendly, retryable network state.
//!
//! `IntegrityFailure` (reached the network, bytes don't verify — security) and `Unreachable`
//! (couldn't reach the network — retryable) are never conflated. A malformed URN, a not-found
//! resource, and a reachable protocol error are hard [`ResolveError`]s.

/// The resolved bytes plus their content type. Only ever the VERIFIED content of a
/// [`ResolveOutcome::Success`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedData {
    /// The verified, decrypted resource bytes.
    pub bytes: Vec<u8>,
    /// The MIME type.
    pub content_type: String,
}

impl ResolvedData {
    /// Construct resolved data.
    pub fn new(bytes: Vec<u8>, content_type: String) -> Self {
        ResolvedData {
            bytes,
            content_type,
        }
    }
}

/// The typed result of a resolve. The three cases are exhaustive and never conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// Verified, decrypted content.
    Success(ResolvedData),
    /// The served bytes failed integrity verification — a hard, fail-closed security failure. The
    /// unverified bytes are NEVER carried here.
    IntegrityFailure,
    /// Every transport tier was unreachable — a friendly, retryable network state.
    Unreachable,
}

impl ResolveOutcome {
    /// `true` iff this is verified content.
    pub fn is_success(&self) -> bool {
        matches!(self, ResolveOutcome::Success(_))
    }

    /// The verified data, if this is a success.
    pub fn data(&self) -> Option<&ResolvedData> {
        match self {
            ResolveOutcome::Success(d) => Some(d),
            _ => None,
        }
    }

    /// A stable machine-readable tag: `"success"` / `"integrity_failure"` / `"unreachable"`.
    pub fn kind(&self) -> &'static str {
        match self {
            ResolveOutcome::Success(_) => "success",
            ResolveOutcome::IntegrityFailure => "integrity_failure",
            ResolveOutcome::Unreachable => "unreachable",
        }
    }
}

/// Options for a resolve. All optional; a resolver applies its own §5.3-ladder defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOptions {
    /// An explicit endpoint override. When set it WINS and skips the ladder (§5.3): a loopback host
    /// may use the node path; any other host is a verified rpc endpoint.
    pub endpoint: Option<String>,
    /// Override the "connect a node" CTA target the resolver renders for an unreachable outcome.
    pub connect_url: Option<String>,
}

/// A hard, fail-closed resolution failure. Distinct from [`ResolveOutcome::Unreachable`] (the
/// network-down state) and [`ResolveOutcome::IntegrityFailure`] (bytes fetched but unverifiable).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The input was not a syntactically valid DIG URN.
    #[error("invalid DIG URN: {0}")]
    Parse(String),

    /// A transport-level failure talking to a specific endpoint (DNS, TLS, connection, timeout,
    /// malformed HTTP). Not "every tier down" (that is [`ResolveOutcome::Unreachable`]).
    #[error("transport error: {0}")]
    Transport(String),

    /// The RPC endpoint returned a protocol error, or a response the resolver cannot interpret.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// The resource does not exist in the store at the resolved root. A hard, fail-closed verdict.
    #[error("resource not found")]
    NotFound,

    /// A rootless URN was resolved over the untrusted blind tier, where the trust root cannot be
    /// established without trusting the gateway. Pin a root in the URN, or resolve via a loopback
    /// node. Fail-closed — the resolver will NOT verify against a gateway-asserted root.
    #[error(
        "a root-pinned URN is required to verify over the public gateway \
         (rootless URNs are not chain-verified there)"
    )]
    RootRequired,

    /// The served ciphertext failed integrity verification against the chain-anchored root (tampered
    /// bytes, a non-chaining proof, or a decoy from a wrong store). FAIL-CLOSED: bytes discarded.
    #[error("inclusion verification failed: {0}")]
    VerifyFailed(String),

    /// The verified ciphertext did not decrypt under the URN's key (AEAD tag failure — wrong
    /// key/salt or corruption), or an untrusted chunk-length plan was inconsistent. FAIL-CLOSED.
    #[error("decryption failed (wrong key/salt or corrupt ciphertext)")]
    DecryptFailed,
}

/// Result alias for resolution operations.
pub type Result<T> = core::result::Result<T, ResolveError>;

/// The resolution contract: turn a [`DigUrn`](crate::DigUrn) into a typed [`ResolveOutcome`].
///
/// A concrete implementation walks the §5.3 node-first ladder over its own transport, verifies via
/// the [`crate::verify`] contract, and MUST honour the fail-closed outcome distinction above — never
/// returning unverified bytes as a `Success`.
#[allow(async_fn_in_trait)] // A contract crate; a boxed-future/`Send` bound is the caller's choice.
pub trait UrnResolver {
    /// Resolve a URN string to a typed outcome, or a hard [`ResolveError`].
    async fn resolve(&self, urn: &str, opts: &ResolveOptions) -> Result<ResolveOutcome>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_accessors_are_exhaustive() {
        let ok = ResolveOutcome::Success(ResolvedData::new(vec![1, 2], "text/plain".into()));
        assert!(ok.is_success());
        assert_eq!(ok.kind(), "success");
        assert_eq!(ok.data().unwrap().bytes, vec![1, 2]);

        assert_eq!(ResolveOutcome::IntegrityFailure.kind(), "integrity_failure");
        assert!(!ResolveOutcome::IntegrityFailure.is_success());
        assert!(ResolveOutcome::IntegrityFailure.data().is_none());

        assert_eq!(ResolveOutcome::Unreachable.kind(), "unreachable");
        assert!(ResolveOutcome::Unreachable.data().is_none());
    }

    #[test]
    fn errors_render_stable_messages() {
        assert!(ResolveError::RootRequired
            .to_string()
            .contains("root-pinned"));
        assert_eq!(ResolveError::NotFound.to_string(), "resource not found");
    }
}
