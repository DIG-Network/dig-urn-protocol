//! [`Bytes32`] — the crate's own 32-byte value type.
//!
//! `dig-urn-protocol` is a LEAF crate (no `dig-*` dependencies), so it defines its own newtype for
//! the 32-byte identifiers a URN carries — the store id, the generation root hash, the retrieval
//! key, and merkle roots/leaves. It is byte-compatible with `digstore_core::Bytes32`: a caller
//! bridges the two with `Bytes32::from(bytes.0)` / `bytes.0`.

use core::fmt;

/// A 32-byte value (a store id, a root hash, a retrieval key, or a merkle node).
///
/// Rendered canonically as **lowercase** hex on the wire; parsing rejects any input that is not
/// exactly 64 hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    /// Parse exactly 64 hex digits into 32 bytes. Rejects wrong-length or non-hex input.
    ///
    /// Uppercase hex is accepted on input (so an over-tolerant producer round-trips), but
    /// [`Bytes32::to_hex`] always re-emits lowercase — the canonical form.
    pub fn from_hex(hex_str: &str) -> Result<Bytes32, InvalidBytes32> {
        if hex_str.len() != 64 {
            return Err(InvalidBytes32);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out).map_err(|_| InvalidBytes32)?;
        Ok(Bytes32(out))
    }

    /// Render as 64 lowercase hex digits (the canonical wire form).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(raw: [u8; 32]) -> Self {
        Bytes32(raw)
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes32({})", self.to_hex())
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The input was not exactly 64 lowercase-or-uppercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBytes32;

impl fmt::Display for InvalidBytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("value must be exactly 64 hex digits (32 bytes)")
    }
}

impl std::error::Error for InvalidBytes32 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_lowercase_hex() {
        let h = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        assert_eq!(Bytes32::from_hex(h).unwrap().to_hex(), h);
    }

    #[test]
    fn normalizes_uppercase_to_lowercase() {
        let upper = "AABB".to_string() + &"00".repeat(30);
        let lower = "aabb".to_string() + &"00".repeat(30);
        assert_eq!(Bytes32::from_hex(&upper).unwrap().to_hex(), lower);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(Bytes32::from_hex("1111"), Err(InvalidBytes32));
        assert_eq!(Bytes32::from_hex(&"11".repeat(33)), Err(InvalidBytes32));
    }

    #[test]
    fn rejects_non_hex() {
        assert_eq!(Bytes32::from_hex(&"zz".repeat(32)), Err(InvalidBytes32));
    }

    #[test]
    fn from_array_and_display() {
        let b = Bytes32::from([0x11u8; 32]);
        assert_eq!(b.to_string(), "11".repeat(32));
        assert!(format!("{b:?}").contains(&"11".repeat(32)));
    }
}
