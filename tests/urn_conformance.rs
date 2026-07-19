//! Frozen URN conformance vectors (gap #128), imported BYTE-IDENTICALLY from
//! `digstore-core/tests/fixtures/urn_conformance.json`. Every implementation of the DIG URN grammar
//! (this crate, the SDK, the extension, the browser) is expected to pass this same corpus, so the
//! grammar can never drift. Tightening the grammar (rejecting non-`chia` chains, requiring a
//! resource) is forbidden — it would break these frozen vectors and existing on-chain artifacts.

use dig_urn_protocol::DigUrn;
use serde_json::Value;

const CORPUS: &str = include_str!("fixtures/urn_conformance.json");

fn corpus() -> Value {
    serde_json::from_str(CORPUS).expect("conformance fixture is valid JSON")
}

#[test]
fn canonical_chain_matches_the_crate_constant() {
    assert_eq!(
        corpus()["canonical_chain"].as_str().unwrap(),
        dig_urn_protocol::CANONICAL_CHAIN
    );
}

#[test]
fn every_invalid_vector_is_rejected() {
    for case in corpus()["invalid"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();
        assert!(
            DigUrn::parse(input).is_err(),
            "vector '{name}' ({input:?}) must be rejected but parsed"
        );
    }
}

#[test]
fn every_valid_vector_parses_canonicalises_and_derives_the_key() {
    for case in corpus()["valid"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let urn = DigUrn::parse(input).unwrap_or_else(|e| panic!("vector '{name}' rejected: {e}"));

        assert_eq!(
            urn.chain,
            case["chain"].as_str().unwrap(),
            "chain mismatch in '{name}'"
        );
        assert_eq!(
            urn.store_id_hex(),
            case["store_id_hex"].as_str().unwrap(),
            "store_id mismatch in '{name}'"
        );

        let expected_root = case["root_hash_hex"].as_str();
        assert_eq!(
            urn.root_hex().as_deref(),
            expected_root,
            "root_hash mismatch in '{name}'"
        );

        let expected_resource = case["resource_key"].as_str();
        assert_eq!(
            urn.resource_key.as_deref(),
            expected_resource,
            "resource_key mismatch in '{name}'"
        );

        assert_eq!(
            urn.canonical(),
            case["canonical"].as_str().unwrap(),
            "canonical mismatch in '{name}'"
        );
        assert_eq!(
            urn.retrieval_key_hex(),
            case["retrieval_key_hex"].as_str().unwrap(),
            "retrieval_key mismatch in '{name}' — a change here breaks the frozen corpus"
        );
    }
}
