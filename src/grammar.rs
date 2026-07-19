//! The **single normative grammar** for the DIG URN — the contract every implementation's parser
//! must conform to.
//!
//! Several parsers historically parsed `urn:dig:…` independently (this crate's [`DigUrn`], the
//! `dig-sdk` regex, the extension JS parser, the browser C++ parser) with no shared conformance
//! suite, so they drifted. This module fixes ONE grammar as the source of truth and pins it with a
//! frozen vector file (`tests/fixtures/urn_conformance.json`, imported byte-identically from
//! `digstore_core`) that [`crate::DigUrn`] is tested against; every other port is expected to run
//! the same frozen vectors so all implementations conform to one definition.
//!
//! [`DigUrn`]: crate::DigUrn
//!
//! # Normative grammar (ABNF, RFC 5234)
//!
//! ```abnf
//! dig-urn       = "urn:dig:" chain ":" store-id [ ":" root-hash ] [ "/" resource ]
//!
//! chain         = 1*chain-char        ; non-empty; canonical value is "chia"
//! chain-char    = ALPHA / DIGIT / "-" ; (see "Chain segment" note — the parser is
//!                                     ; permissive; deployed content uses "chia")
//!
//! store-id      = 64HEXDIG            ; the CHIP-0035 singleton launcher id, 32 bytes
//! root-hash     = 64HEXDIG            ; a capsule's on-chain root, 32 bytes (optional)
//! resource      = *pchar             ; the resource path/key, verbatim after the
//!                                     ; FIRST "/", may itself contain "/" (optional)
//!
//! HEXDIG        = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"   ; lowercase, canonical
//! ```
//!
//! Notes that make the grammar *normative* (the parser's actual behaviour):
//!
//! * **Prefix** is the literal `urn:dig:`. Anything else is rejected.
//! * **Resource split is at the FIRST `/`.** Everything before it is `chain:store-id[:root-hash]`;
//!   everything after is the resource (which may contain further `/`). A trailing-but-empty resource
//!   (`…/`) parses as `resource = ""` (an empty string), distinct from an absent resource.
//! * **Colon arity in the head is exactly 2 or 3 segments** (`chain:store-id` or
//!   `chain:store-id:root-hash`). A 4th `:`-segment is rejected.
//! * **`store-id` and `root-hash` are 32-byte lowercase hex.** A non-hex or wrong-length value is
//!   rejected.
//! * **Canonical form** re-emits `urn:dig:<chain>:<store-id-hex>[:<root-hash-hex>][/<resource>]`,
//!   store-id and root-hash as lowercase hex, omitting absent fields. Parsing then re-canonicalising
//!   is idempotent for any canonical input.
//! * **Retrieval key** is `SHA-256(canonical())` as raw 32 bytes (lowercase hex on the wire) — the
//!   URN-identity key the frozen corpus pins. The root-independent CONTENT key a resolver uses to
//!   fetch is `SHA-256(canonical_rootless())` (see `DigUrn::content_key`).
//!
//! # The `?salt` query — intentionally NOT part of the URN identity
//!
//! The secret salt is a private-store *decryption-key* input, never part of the canonical URN or the
//! retrieval key: a private store derives its AES key from `canonical_urn + salt`, but the retrieval
//! key (what the host sees) stays `SHA-256(canonical_urn)` — by design the host cannot tell a private
//! store from a public one. So this grammar has **no `?salt` production**: the core parser leaves a
//! `?salt=…` suffix inside the resource. Any edge parser that peels `?salt` MUST do so OUTSIDE the
//! canonical-URN derivation (as [`crate::DigUrn::parse_with_salt`] does), and a surfaced salt MUST be
//! exactly 32 bytes / 64 lowercase hex.
//!
//! # Back-compatibility (frozen corpus)
//!
//! The grammar MUST accept every historically-published URN: multi-chain labels (`chia`, `mainnet`,
//! `testnet`), and the bare resourceless form `urn:dig:chia:<store>`. Tightening the parser (e.g.
//! rejecting non-`chia` chains, or making `/resource` mandatory) is forbidden — it would break the
//! frozen KAT corpus and existing on-chain-anchored artifacts.

/// The normative URN grammar as ABNF (RFC 5234) text — the machine-/human-readable single source of
/// truth, embedded so an agent can introspect it without leaving the crate. Kept byte-identical to
/// the module-doc grammar block above and to `digstore_core::urn_grammar::URN_ABNF`.
pub const URN_ABNF: &str = "\
dig-urn       = \"urn:dig:\" chain \":\" store-id [ \":\" root-hash ] [ \"/\" resource ]\n\
chain         = 1*chain-char        ; non-empty; canonical value is \"chia\"\n\
chain-char    = ALPHA / DIGIT / \"-\"\n\
store-id      = 64HEXDIG            ; CHIP-0035 singleton launcher id, 32 bytes\n\
root-hash     = 64HEXDIG            ; a capsule's on-chain root, 32 bytes (optional)\n\
resource      = *pchar             ; verbatim after the FIRST \"/\" (optional)\n\
HEXDIG        = DIGIT / \"a\" / \"b\" / \"c\" / \"d\" / \"e\" / \"f\"\n";

/// The literal URN prefix. Anything not starting with this is rejected.
pub const URN_PREFIX: &str = "urn:dig:";

/// The canonical chain tag a conforming URN SHOULD carry. Other labels (`mainnet`, `testnet`) remain
/// ACCEPTED for back-compat with the frozen corpus.
pub const CANONICAL_CHAIN: &str = "chia";

/// The default resource an empty/absent resource key resolves to (the store's landing view).
pub const DEFAULT_RESOURCE_KEY: &str = "index.html";

/// The `?salt=` query marker an edge parser peels off before delegating to the core parser.
pub const SALT_QUERY_MARKER: &str = "?salt=";
