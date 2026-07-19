//! The browser content-VERIFICATION contract — how a blind client turns opaque gateway bytes into
//! verified plaintext, **fail-closed**, over INJECTED crypto primitives.
//!
//! # Trust model
//!
//! On the blind (rpc/gateway) tier a client fetches opaque ciphertext + an inclusion proof from an
//! UNTRUSTED public gateway. The gateway can lie about anything except what the chain anchors, so the
//! client MUST verify every byte against the URN's PINNED root (obtained from the chain, NEVER from
//! the gateway) before trusting it. The node tier does NOT use this contract — a loopback node
//! decrypts + verifies server-side and returns plaintext under a loopback trust boundary.
//!
//! # The normative rules (all enforced here, fail-closed)
//!
//! 1. **Rootless-URN rejection.** A rootless URN cannot be verified on the blind tier (there is no
//!    trusted root) → [`ResolveError::RootRequired`]. Use [`require_blind_root`].
//! 2. **Leaf binding.** `leaf == SHA-256(ciphertext)` — the served ciphertext MUST be the proof's
//!    declared leaf. (This crate owns this SHA-256 check; see [`resource_leaf`].)
//! 3. **Path fold.** The proof's merkle path MUST fold consistently to `proof.root` — enforced by the
//!    injected [`ContentCrypto::decode_and_fold`] (returns `None` on any inconsistency).
//! 4. **Root anchoring.** `proof.root == trusted_root` — the folded root MUST equal the
//!    chain-anchored root pinned by the URN. A decoy / wrong-store / tampered response can never
//!    chain to the real root.
//! 5. **Gate-then-decrypt.** Decryption happens ONLY after 1–4 pass; the AEAD tag is the final gate.
//! 6. **u64-bounded chunk split.** The gateway-supplied `chunk_lens` is NOT covered by the proof, so
//!    it is UNTRUSTED: it is accumulated and bounded in `u64` and sliced against the remaining buffer
//!    so a crafted length can never wrap `usize` on wasm32 and slice out of bounds (→ `panic=abort`,
//!    a wallet crash). Any inconsistency fails closed as [`ResolveError::DecryptFailed`].
//!
//! The merkle-fold and AES primitives are supplied by the caller (`digstore_core`) via
//! [`ContentCrypto`] — this crate reimplements NO merkle or AES crypto, so it can never skew from
//! the canonical read-crypto.

use crate::bytes::Bytes32;
use crate::resolve::{ResolveError, Result};
use crate::urn::{DigUrn, SecretSalt};
use sha2::{Digest, Sha256};

/// A decoded, folded inclusion proof: its declared leaf and the root its merkle path folds to.
///
/// The injected [`ContentCrypto::decode_and_fold`] produces this from the wire proof, returning
/// `Some` ONLY when the path folds consistently to a single root (rule 3). The remaining equalities
/// (leaf-binding, root-anchoring) are enforced by [`verify_inclusion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldedProof {
    /// The leaf the proof declares (MUST equal `SHA-256(ciphertext)` — rule 2).
    pub leaf: Bytes32,
    /// The root the proof's path folds to (MUST equal the chain-anchored `trusted_root` — rule 4).
    pub root: Bytes32,
}

/// The crypto primitives this contract INJECTS from `digstore_core` (never reimplemented here).
pub trait ContentCrypto {
    /// Decode the wire-encoded inclusion `proof` and fold its merkle path, returning the declared
    /// leaf and folded root. Return `None` on ANY malformed encoding or internally-inconsistent path
    /// (fail-closed) — the path-fold rule (3) lives here.
    fn decode_and_fold(&self, proof: &[u8]) -> Option<FoldedProof>;

    /// AES-256-GCM-SIV open ONE ciphertext `chunk` under the key derived from `urn`'s rootless
    /// canonical form + optional `salt`. Return `None` on an AEAD tag failure (fail-closed).
    fn decrypt_chunk(
        &self,
        urn: &DigUrn,
        salt: Option<&SecretSalt>,
        chunk: &[u8],
    ) -> Option<Vec<u8>>;
}

/// The content leaf: `SHA-256(ciphertext)` (rule 2). This is the only crypto this leaf crate
/// performs directly; it matches `digstore_core::resource_leaf`.
pub fn resource_leaf(ciphertext: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    Bytes32(hasher.finalize().into())
}

/// Rule 1: obtain the trusted root for a BLIND-tier verify, rejecting a rootless URN.
///
/// The root MUST come from the chain (the caller passes what it read from the anchor), NEVER from the
/// gateway. A URN with no pinned root cannot be verified blind → [`ResolveError::RootRequired`].
pub fn require_blind_root(urn: &DigUrn) -> Result<Bytes32> {
    urn.root_hash.ok_or(ResolveError::RootRequired)
}

/// Rules 2–4: the integrity gate. The served `ciphertext` must be the proof's leaf, the path must
/// fold to a root (via the injected decoder), and that root must equal `trusted_root`. Any failure is
/// a hard fail-closed [`ResolveError::VerifyFailed`].
pub fn verify_inclusion<C: ContentCrypto>(
    crypto: &C,
    ciphertext: &[u8],
    proof: &[u8],
    trusted_root: &Bytes32,
) -> Result<()> {
    let folded = crypto.decode_and_fold(proof).ok_or_else(|| {
        ResolveError::VerifyFailed("inclusion proof is malformed or inconsistent".into())
    })?;

    if folded.leaf != resource_leaf(ciphertext) {
        return Err(ResolveError::VerifyFailed(
            "content does not match proof leaf (tampered ciphertext)".into(),
        ));
    }
    if &folded.root != trusted_root {
        return Err(ResolveError::VerifyFailed(
            "merkle root does not match the chain-anchored trusted root".into(),
        ));
    }
    Ok(())
}

/// Rule 6: split concatenated chunk ciphertexts into byte ranges under a u64-bounded plan.
///
/// `chunk_lens` is the UNTRUSTED per-chunk ciphertext byte lengths in order (no wire framing). An
/// empty plan is the common single-chunk resource (`[ciphertext.len()]`). The lengths are summed and
/// bounded in `u64` (never `usize`, so no wasm32 wrap), the total must equal the buffer length, and
/// each window is sliced defensively against the remaining buffer. Any inconsistency →
/// [`ResolveError::DecryptFailed`], never a panic.
pub fn chunk_ranges(ciphertext_len: usize, chunk_lens: &[u32]) -> Result<Vec<(usize, usize)>> {
    let ct_len = ciphertext_len as u64;
    let plan: Vec<u64> = if chunk_lens.is_empty() {
        vec![ct_len]
    } else {
        chunk_lens.iter().map(|&l| l as u64).collect()
    };

    let mut total: u64 = 0;
    for &len in &plan {
        total = total.checked_add(len).ok_or(ResolveError::DecryptFailed)?;
    }
    if total != ct_len {
        return Err(ResolveError::DecryptFailed);
    }

    let mut ranges = Vec::with_capacity(plan.len());
    let mut start: usize = 0;
    for len in plan {
        let len = usize::try_from(len).map_err(|_| ResolveError::DecryptFailed)?;
        let end = start
            .checked_add(len)
            .filter(|&e| e <= ciphertext_len)
            .ok_or(ResolveError::DecryptFailed)?;
        ranges.push((start, end));
        start = end;
    }
    Ok(ranges)
}

/// Rule 5 (confidentiality half): decrypt the verified ciphertext. Splits by [`chunk_ranges`] and
/// AES-opens each chunk in order via the injected [`ContentCrypto::decrypt_chunk`]. A tag failure on
/// any chunk fails closed with [`ResolveError::DecryptFailed`].
pub fn decrypt<C: ContentCrypto>(
    crypto: &C,
    urn: &DigUrn,
    salt: Option<&SecretSalt>,
    ciphertext: &[u8],
    chunk_lens: &[u32],
) -> Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (start, end) in chunk_ranges(ciphertext.len(), chunk_lens)? {
        let chunk = &ciphertext[start..end];
        let pt = crypto
            .decrypt_chunk(urn, salt, chunk)
            .ok_or(ResolveError::DecryptFailed)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

/// The full blind-tier pipeline: **gate-then-decrypt** (rules 1–6). Rejects a rootless URN, verifies
/// inclusion against `trusted_root`, then decrypts — decryption is reached ONLY after verification
/// passes.
pub fn verify_and_decrypt<C: ContentCrypto>(
    crypto: &C,
    urn: &DigUrn,
    salt: Option<&SecretSalt>,
    ciphertext: &[u8],
    proof: &[u8],
    trusted_root: &Bytes32,
    chunk_lens: &[u32],
) -> Result<Vec<u8>> {
    verify_inclusion(crypto, ciphertext, proof, trusted_root)?;
    decrypt(crypto, urn, salt, ciphertext, chunk_lens)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double: XOR "decrypts", and folds a proof whose bytes are `leaf(32) || root(32)`.
    struct FakeCrypto;
    impl ContentCrypto for FakeCrypto {
        fn decode_and_fold(&self, proof: &[u8]) -> Option<FoldedProof> {
            if proof.len() != 64 {
                return None;
            }
            let mut leaf = [0u8; 32];
            let mut root = [0u8; 32];
            leaf.copy_from_slice(&proof[..32]);
            root.copy_from_slice(&proof[32..]);
            Some(FoldedProof {
                leaf: Bytes32(leaf),
                root: Bytes32(root),
            })
        }
        fn decrypt_chunk(
            &self,
            _urn: &DigUrn,
            _salt: Option<&SecretSalt>,
            chunk: &[u8],
        ) -> Option<Vec<u8>> {
            Some(chunk.iter().map(|b| b ^ 0xAA).collect())
        }
    }

    fn urn() -> DigUrn {
        DigUrn::parse(&format!("urn:dig:chia:{}/a.bin", "11".repeat(32))).unwrap()
    }

    fn valid_proof(ciphertext: &[u8], root: &Bytes32) -> Vec<u8> {
        let mut p = resource_leaf(ciphertext).0.to_vec();
        p.extend_from_slice(&root.0);
        p
    }

    #[test]
    fn require_blind_root_rejects_rootless() {
        assert_eq!(require_blind_root(&urn()), Err(ResolveError::RootRequired));
        let rooted = DigUrn::parse(&format!(
            "urn:dig:chia:{}:{}/a",
            "11".repeat(32),
            "22".repeat(32)
        ))
        .unwrap();
        assert!(require_blind_root(&rooted).is_ok());
    }

    #[test]
    fn verify_and_decrypt_happy_path() {
        let ct = vec![0x01u8; 8];
        let root = Bytes32([0x33u8; 32]);
        let proof = valid_proof(&ct, &root);
        let out = verify_and_decrypt(&FakeCrypto, &urn(), None, &ct, &proof, &root, &[]).unwrap();
        assert_eq!(out, vec![0x01 ^ 0xAA; 8]);
    }

    #[test]
    fn tampered_ciphertext_fails_leaf_binding() {
        let ct = vec![0x01u8; 8];
        let root = Bytes32([0x33u8; 32]);
        let proof = valid_proof(&ct, &root);
        let tampered = vec![0x02u8; 8];
        assert!(matches!(
            verify_inclusion(&FakeCrypto, &tampered, &proof, &root),
            Err(ResolveError::VerifyFailed(_))
        ));
    }

    #[test]
    fn wrong_trusted_root_fails_anchoring() {
        let ct = vec![0x01u8; 8];
        let proof = valid_proof(&ct, &Bytes32([0x33u8; 32]));
        let other_root = Bytes32([0x44u8; 32]);
        assert!(matches!(
            verify_inclusion(&FakeCrypto, &ct, &proof, &other_root),
            Err(ResolveError::VerifyFailed(_))
        ));
    }

    #[test]
    fn malformed_proof_fails_closed() {
        let ct = vec![0x01u8; 8];
        assert!(matches!(
            verify_inclusion(&FakeCrypto, &ct, &[0u8; 10], &Bytes32([0x33u8; 32])),
            Err(ResolveError::VerifyFailed(_))
        ));
    }

    #[test]
    fn chunk_ranges_empty_is_single_chunk() {
        assert_eq!(chunk_ranges(10, &[]).unwrap(), vec![(0, 10)]);
    }

    #[test]
    fn chunk_ranges_splits_in_order() {
        assert_eq!(chunk_ranges(10, &[3, 7]).unwrap(), vec![(0, 3), (3, 10)]);
    }

    #[test]
    fn chunk_ranges_rejects_total_mismatch() {
        assert_eq!(chunk_ranges(10, &[999]), Err(ResolveError::DecryptFailed));
    }

    #[test]
    fn chunk_ranges_rejects_overflow_without_panic() {
        // `[len+2^31, 2^31]` wraps usize on wasm32; the u64-checked total must reject it cleanly.
        let bad = [(1u32 << 31) + 10, 1u32 << 31];
        assert_eq!(chunk_ranges(10, &bad), Err(ResolveError::DecryptFailed));
    }

    #[test]
    fn decrypt_maps_tag_failure_to_decryptfailed() {
        struct AlwaysFail;
        impl ContentCrypto for AlwaysFail {
            fn decode_and_fold(&self, _p: &[u8]) -> Option<FoldedProof> {
                None
            }
            fn decrypt_chunk(
                &self,
                _u: &DigUrn,
                _s: Option<&SecretSalt>,
                _c: &[u8],
            ) -> Option<Vec<u8>> {
                None
            }
        }
        assert_eq!(
            decrypt(&AlwaysFail, &urn(), None, &[0u8; 4], &[]),
            Err(ResolveError::DecryptFailed)
        );
    }
}
