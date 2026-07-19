# dig-urn-protocol

The **canonical DIG content-addressing + server-untrusted verification contract**: the one definition
of how a DIG URN names content and how a blind client turns opaque gateway bytes into verified
plaintext, **fail-closed**.

`dig-urn-protocol` is a **leaf crate** — it has NO `dig-*` dependencies and NO transport
(reqwest/tokio). The merkle-fold and AES primitives are INJECTED by the caller (`digstore_core`), so
this crate reimplements no merkle or AES crypto and can never skew from the canonical read-crypto. It
performs only SHA-256 (the retrieval key + the content leaf).

Licensed under **Apache-2.0 OR MIT**. Normative contract: [`SPEC.md`](./SPEC.md).

---

## Protocol interface — at-a-glance reference

Everything below is the complete public contract. An implementation in any language conforms by
matching it (and passing the frozen vectors in `tests/fixtures/`).

### The `urn:dig:` grammar (ABNF, RFC 5234)

```abnf
dig-urn       = "urn:dig:" chain ":" store-id [ ":" root-hash ] [ "/" resource ]

chain         = 1*chain-char        ; non-empty; canonical value is "chia"
chain-char    = ALPHA / DIGIT / "-"
store-id      = 64HEXDIG            ; CHIP-0035 singleton launcher id, 32 bytes
root-hash     = 64HEXDIG            ; a capsule's on-chain root, 32 bytes (OPTIONAL)
resource      = *pchar             ; verbatim after the FIRST "/" (OPTIONAL)
HEXDIG        = DIGIT / "a".."f"    ; lowercase, canonical
```

Full form with the out-of-band salt query (peeled OUTSIDE the canonical identity):

```
urn:dig:<chain>:<store-id>[:<root-hash>][/<resource>][?salt=<64hex>]
```

Normative parse rules:

| Rule | Behaviour |
|------|-----------|
| Prefix | Literal `urn:dig:`. Anything else is rejected. |
| Resource split | At the **FIRST** `/`. The resource may itself contain `/`. |
| Colon arity (head) | Exactly 2 or 3 segments (`chain:store-id` or `chain:store-id:root-hash`). A 4th is rejected. |
| store-id / root-hash | Exactly 64 lowercase hex (32 bytes). Non-hex / wrong-length rejected. |
| Resource optionality | Resource is **OPTIONAL**. Bare `urn:dig:chia:<store>` names the store. |
| Trailing slash | `…/` → `resource = ""` (empty), **distinct** from an absent resource. |
| Chain back-compat | `chia` (canonical), `mainnet`, `testnet` all accepted. Do **not** tighten — it would break the frozen corpus. |
| `?salt=` | NOT part of the URN identity. Peeled off before parsing; a surfaced salt MUST be exactly 32 bytes / 64 hex. The core parser leaves an un-peeled `?salt=` inside the resource. |

### `DigUrn` type

```rust
pub struct DigUrn {
    pub chain: String,             // "chia" | "mainnet" | "testnet" | …
    pub store_id: Bytes32,         // singleton launcher id
    pub root_hash: Option<Bytes32>,// pinned generation root; trust anchor ONLY, never a key input
    pub resource_key: Option<String>, // None=absent, Some("")=trailing slash, Some("p")=path
}
```

### Derivation

| Function | Definition |
|----------|------------|
| `canonical()` | `urn:dig:<chain>:<store-hex>[:<root-hex>][/<resource>]`, lowercase hex, absent fields omitted. Idempotent. |
| `canonical_rootless()` | `canonical()` with `root_hash = None` and `resource_key = effective_resource_key()`. |
| `effective_resource_key()` | The resource, defaulting absent/empty → `index.html` (`DEFAULT_RESOURCE_KEY`). |
| `retrieval_key()` | `SHA-256(canonical())` — the URN-identity key (pins the root). Matches `digstore_core::Urn` and the frozen corpus. |
| `content_key()` | `SHA-256(canonical_rootless())` — root-independent; the fetch identifier + AES-key seed, stable across generations. |
| `salt_bytes(hex)` | Validate a peeled salt → `SecretSalt` (exactly 64 hex). |

Constants: `URN_PREFIX = "urn:dig:"`, `CANONICAL_CHAIN = "chia"`, `DEFAULT_RESOURCE_KEY =
"index.html"`, `SALT_QUERY_MARKER = "?salt="`, `URN_ABNF` (the grammar text).

### Resolution interface

```rust
pub trait UrnResolver {
    async fn resolve(&self, urn: &str, opts: &ResolveOptions) -> Result<ResolveOutcome>;
}

pub enum ResolveOutcome {
    Success(ResolvedData),  // verified, decrypted content
    IntegrityFailure,       // bytes fetched but failed verify — fail-closed; bytes NEVER carried
    Unreachable,            // every tier down — retryable
}                           // .kind() → "success" | "integrity_failure" | "unreachable"

pub struct ResolvedData   { pub bytes: Vec<u8>, pub content_type: String }
pub struct ResolveOptions { pub endpoint: Option<String>, pub connect_url: Option<String> }
```

`ResolveError` (catalogued, stable): `Parse` · `Transport` · `Rpc` · `NotFound` · `RootRequired` ·
`VerifyFailed(String)` · `DecryptFailed`. `IntegrityFailure` (reached network, unverifiable) and
`Unreachable` (network down) are never conflated.

### Browser content-verification contract

Injected primitives (supplied by `digstore_core` — this crate reimplements neither):

```rust
pub struct FoldedProof { pub leaf: Bytes32, pub root: Bytes32 }

pub trait ContentCrypto {
    // Decode + fold the wire proof. Some(FoldedProof) ONLY if the path folds consistently (rule 3).
    fn decode_and_fold(&self, proof: &[u8]) -> Option<FoldedProof>;
    // AES-256-GCM-SIV open one chunk under the URN-derived key. None on tag failure (fail-closed).
    fn decrypt_chunk(&self, urn: &DigUrn, salt: Option<&SecretSalt>, chunk: &[u8]) -> Option<Vec<u8>>;
}
```

Verification input (conceptual `VerificationInput`): `{ urn, salt?, ciphertext, inclusion_proof
(wire bytes), chunk_lens (untrusted per-chunk ciphertext lengths), trusted_root (from the CHAIN) }`.

Normative verify rules (all fail-closed, enforced by this crate):

| # | Rule | Enforced by |
|---|------|-------------|
| 1 | **Rootless rejection** — a rootless URN cannot be verified on the blind tier → `RootRequired`. | `require_blind_root(urn)` |
| 2 | **Leaf binding** — `proof.leaf == SHA-256(ciphertext)`. | `verify_inclusion` (`resource_leaf`) |
| 3 | **Path fold** — the proof path folds consistently to `proof.root`. | injected `decode_and_fold` |
| 4 | **Root anchoring** — `proof.root == trusted_root` (the chain-anchored root; NEVER the gateway's). | `verify_inclusion` |
| 5 | **Gate-then-decrypt** — decrypt ONLY after 1–4 pass; the AEAD tag is the final gate. | `verify_and_decrypt` |
| 6 | **u64-bounded chunk split** — `chunk_lens` summed/bounded in `u64` (no `usize` wrap on wasm32), total must equal the buffer, each window sliced defensively → `DecryptFailed` on any inconsistency, never a panic. | `chunk_ranges` |

Pipeline entry points:

```rust
fn resource_leaf(ciphertext: &[u8]) -> Bytes32;                 // rule 2 (SHA-256)
fn require_blind_root(urn: &DigUrn) -> Result<Bytes32>;         // rule 1
fn verify_inclusion<C: ContentCrypto>(c, ciphertext, proof, trusted_root) -> Result<()>;   // 2–4
fn chunk_ranges(ciphertext_len, chunk_lens) -> Result<Vec<(usize, usize)>>;                 // 6
fn decrypt<C: ContentCrypto>(c, urn, salt, ciphertext, chunk_lens) -> Result<Vec<u8>>;      // 5,6
fn verify_and_decrypt<C: ContentCrypto>(c, urn, salt, ciphertext, proof, trusted_root, chunk_lens)
    -> Result<Vec<u8>>;                                         // full blind pipeline (1–6)
```

The node tier does NOT use this contract — a loopback node decrypts + verifies server-side and
returns plaintext under a loopback trust boundary.

### Relationship to other crates

- **`digstore_core`** — supplies the injected merkle-fold + AES primitives; `Bytes32` is
  byte-compatible (`Bytes32::from(other.0)`).
- **`dig-rpc-protocol`** — this crate consumes its `PublicRead` fetch contract *conceptually*; it does
  not depend on it or duplicate any RPC method. A concrete `UrnResolver` wires the two together.

## Conformance

- `tests/fixtures/urn_conformance.json` — the frozen URN vectors, imported **byte-identically** from
  `digstore_core` (URN → canonical → retrieval-key). Every URN implementation must pass these.
- `tests/fixtures/inclusion_proof_vectors.json` — golden `resource_leaf` (SHA-256) + `chunk_ranges`
  vectors pinning the security-critical logic this crate owns directly.
