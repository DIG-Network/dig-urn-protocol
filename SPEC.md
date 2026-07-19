# dig-urn-protocol — Specification

Normative contract for the DIG content-addressing scheme and the server-untrusted content-
verification pipeline. An independent reimplementation (in any language) is conformant iff it
satisfies every MUST here and passes the frozen vectors in `tests/fixtures/`.

Keywords MUST / SHOULD / MAY per RFC 2119.

## 1. Scope

This crate OWNS three contracts and nothing else:

1. the `urn:dig:` scheme — grammar, canonical form, key derivation;
2. the resolution INTERFACE — the outcome/error taxonomy a resolver exposes;
3. the browser content-VERIFICATION contract — the fail-closed gate-then-decrypt pipeline over
   INJECTED crypto primitives.

It MUST NOT contain transport (HTTP/RPC/sockets), merkle-tree construction/folding, or AEAD
encryption/decryption. Those are supplied by the caller. This crate performs SHA-256 only.

## 2. The URN grammar (normative)

```abnf
dig-urn       = "urn:dig:" chain ":" store-id [ ":" root-hash ] [ "/" resource ]
chain         = 1*chain-char
chain-char    = ALPHA / DIGIT / "-"
store-id      = 64HEXDIG
root-hash     = 64HEXDIG
resource      = *pchar
HEXDIG        = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

A conforming parser MUST:

- reject any input not beginning with the literal `urn:dig:`;
- split the resource at the **FIRST** `/`; the resource MAY contain further `/`;
- accept exactly 2 or 3 colon-separated head segments and reject a 4th;
- require `store-id` and `root-hash` to be exactly 64 hex digits (32 bytes); parse uppercase hex but
  canonicalise to lowercase;
- treat `root-hash` and `resource` as OPTIONAL — a bare `urn:dig:chia:<store>` is valid and names the
  store, not a resource;
- distinguish `Some("")` (trailing `/`, empty resource) from `None` (absent resource);
- accept any non-empty chain token; `chia` is canonical, `mainnet`/`testnet` MUST remain accepted for
  back-compat. A parser MUST NOT tighten the chain set or make the resource mandatory — doing so would
  break the frozen corpus and existing on-chain-anchored artifacts.

### 2.1 The `?salt=` query

The secret salt is a private-store DECRYPTION-key input, NOT part of the URN identity. The canonical
URN and the retrieval key MUST NOT include the salt (so the host, which sees only the retrieval key,
cannot distinguish a private store from a public one). An edge parser that peels `?salt=` MUST do so
OUTSIDE canonical-URN derivation, MUST reject an empty salt, and MUST require exactly 32 bytes / 64
hex before use as key material. The core parser leaves an un-peeled `?salt=` suffix inside the
resource.

## 3. Derivation (normative)

- `canonical()` = `urn:dig:<chain>:<store-hex>[:<root-hex>][/<resource>]` with lowercase hex and
  absent fields omitted. Parse-then-canonicalise MUST be idempotent for canonical input.
- `effective_resource_key()` = the resource, defaulting absent/empty → `index.html`.
- `canonical_rootless()` = `canonical()` with `root_hash = None` and `resource_key =
  effective_resource_key()`.
- `retrieval_key()` = `SHA-256(canonical())` — the URN-identity key; pins the root. This is the value
  the frozen corpus fixes and MUST match `digstore_core::Urn::retrieval_key` byte-for-byte.
- `content_key()` = `SHA-256(canonical_rootless())` — root-independent; the identifier a resolver uses
  to fetch and the seed for AES key derivation, stable across generations.

## 4. Resolution interface (normative)

A resolver MUST return exactly one of three outcomes and MUST NOT conflate them:

- `Success(ResolvedData)` — VERIFIED, decrypted content;
- `IntegrityFailure` — bytes were fetched but failed verification. The unverified bytes MUST NOT be
  returned (fail-closed);
- `Unreachable` — every transport tier was down; nothing fetched. Retryable.

Hard errors (`ResolveError`): `Parse`, `Transport`, `Rpc`, `NotFound`, `RootRequired`,
`VerifyFailed`, `DecryptFailed`. These codes are stable (§6.2 agent-friendly) and MUST NOT be
renumbered/repurposed.

A resolver MUST honour the §5.3 node-first ladder (explicit override > `dig.local` > `localhost` >
`rpc.dig.net`) and MUST NOT return unverified bytes as a `Success`.

## 5. Content-verification contract (normative, security-critical)

On the blind (rpc/gateway) tier the client fetches opaque ciphertext + an inclusion proof from an
UNTRUSTED gateway and MUST verify against the URN's PINNED root before trusting any byte. The trusted
root MUST come from the chain anchor, NEVER from the gateway.

The pipeline is **gate-then-decrypt** and MUST fail closed at each step:

1. **Rootless rejection** — a URN with no pinned root MUST NOT be verified on the blind tier →
   `RootRequired`.
2. **Leaf binding** — `proof.leaf` MUST equal `SHA-256(ciphertext)`.
3. **Path fold** — the proof path MUST fold consistently to `proof.root` (the injected
   `decode_and_fold` returns `None` otherwise).
4. **Root anchoring** — `proof.root` MUST equal the chain-anchored `trusted_root`.
5. **Gate-then-decrypt** — decryption MUST NOT begin until 1–4 pass; the AEAD tag is the final gate,
   and a tag failure MUST yield `DecryptFailed`.
6. **u64-bounded chunk split** — `chunk_lens` (the per-chunk ciphertext lengths) is gateway-supplied
   and NOT covered by the proof, therefore UNTRUSTED. Implementations MUST accumulate and bound the
   plan in `u64` (never `usize`), MUST require the total to equal the ciphertext length, and MUST
   slice each window defensively against the remaining buffer, so a crafted length can never wrap
   `usize` (wasm32) and slice out of bounds. Any inconsistency MUST yield `DecryptFailed`, never a
   panic. An empty `chunk_lens` denotes the single-chunk resource.

The merkle-fold and AES primitives MUST be injected (`ContentCrypto`); this crate MUST NOT
reimplement them. `resource_leaf = SHA-256(ciphertext)` is the only crypto performed here and MUST
match `digstore_core::resource_leaf`.

## 6. Conformance vectors

- `tests/fixtures/urn_conformance.json` — imported BYTE-IDENTICALLY from `digstore_core`. Every valid
  vector MUST parse, re-canonicalise, and derive the pinned `retrieval_key_hex`; every invalid vector
  MUST be rejected.
- `tests/fixtures/inclusion_proof_vectors.json` — golden `resource_leaf` (SHA-256) and `chunk_ranges`
  vectors, including the overflow/total-mismatch rejection cases. A change to leaf hashing or the
  bounds guard that breaks these is a regression.

## 7. Dependencies

`sha2`, `hex`, `thiserror`, `serde` only. No `dig-*` dependency; no transport. This keeps the crate a
leaf every consumer (node, browser host, resolver, SDK) can adopt without a dependency cycle.
