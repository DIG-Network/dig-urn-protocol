//! Golden vectors for the content-VERIFICATION contract this crate OWNS directly (the merkle-fold
//! and AES primitives are injected, so they are not vectored here): the SHA-256 content leaf (verify
//! rule 2) and the u64-bounded chunk-split plan (verify rule 6). These pin the security-critical
//! logic so a regression in leaf hashing or the overflow guard is caught.

use dig_urn_protocol::{chunk_ranges, resource_leaf, ResolveError};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/inclusion_proof_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("golden vectors are valid JSON")
}

#[test]
fn resource_leaf_matches_golden_sha256() {
    for case in vectors()["leaves"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ct = hex::decode(case["ciphertext_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            resource_leaf(&ct).to_hex(),
            case["leaf_hex"].as_str().unwrap(),
            "leaf mismatch in '{name}' — SHA-256 leaf hashing must not drift"
        );
    }
}

#[test]
fn chunk_ranges_matches_golden_plans_and_rejections() {
    for case in vectors()["chunk_ranges"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let len = case["ciphertext_len"].as_u64().unwrap() as usize;
        let lens: Vec<u32> = case["chunk_lens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();

        let result = chunk_ranges(len, &lens);
        match case["ranges"].as_array() {
            Some(expected) => {
                let expected: Vec<(usize, usize)> = expected
                    .iter()
                    .map(|r| {
                        let r = r.as_array().unwrap();
                        (
                            r[0].as_u64().unwrap() as usize,
                            r[1].as_u64().unwrap() as usize,
                        )
                    })
                    .collect();
                assert_eq!(result.unwrap(), expected, "ranges mismatch in '{name}'");
            }
            None => assert_eq!(
                result,
                Err(ResolveError::DecryptFailed),
                "vector '{name}' must fail closed"
            ),
        }
    }
}
