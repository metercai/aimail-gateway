//! 与 `protocol/vectors/did-signature.json` 对齐的端到端测试。
//!
//! 这个文件是"契约 ↔ 实现"的唯一连接点：向量由 `protocol/vectors/gen_did_vectors.py` 生成，
//! 三仓共用。本 crate 只断言**锚点层**那几组（`payload_hash`、`domain_control`、`constants`）；
//! 邮件层（`content_v1` / `rcpt_hash` / `signing_input` / `header`）属于 `did-sdk`，
//! 本 crate 不得实现、也不在此断言。

use std::path::PathBuf;

use mail_anchor::{
    domain_control, email_binding, ANCHOR_HASH_PREFIX, DOMAIN_CONTROL_TAG, EMAIL_BINDING_TAG,
};
use serde_json::Value;

fn vectors() -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "protocol",
        "vectors",
        "did-signature.json",
    ]
    .iter()
    .collect();
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("vectors must be valid JSON")
}

#[test]
fn constants_match_the_contract() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(c["email_binding_tag"], EMAIL_BINDING_TAG);
    assert_eq!(c["domain_control_tag"], DOMAIN_CONTROL_TAG);
    assert_eq!(c["anchor_hash_prefix"], ANCHOR_HASH_PREFIX);
    assert_eq!(c["anchor_ref_prefix"], "chain:");
    assert_eq!(c["header_name"], "DID-Signature");
    assert_eq!(c["results_header_name"], "DID-Auth-Results");
    assert_eq!(c["system_mail_header"], "X-AIMail-System");
    assert_eq!(c["protocol_version"], "1");
}

#[test]
fn email_binding_payload_hash_matches_vectors() {
    let v = vectors();
    let cases = v["payload_hash"].as_array().expect("payload_hash cases");
    assert!(!cases.is_empty());

    for case in cases {
        let did = case["did"].as_str().unwrap();
        let email = case["email"].as_str().unwrap();
        let issuer = case["issuer_did"].as_str().unwrap();
        let expected = case["hex"].as_str().unwrap();

        assert_eq!(
            email_binding::payload_hash(did, email, issuer).unwrap(),
            expected,
            "case {:?}",
            case["case"]
        );
        assert!(
            email_binding::verify(expected, did, email, issuer).is_ok(),
            "verify must accept its own vector for {:?}",
            case["case"]
        );
    }
}

#[test]
fn email_binding_payload_hash_is_issuer_sensitive() {
    let v = vectors();
    let cases = v["payload_hash"].as_array().unwrap();
    let a = cases[0]["hex"].as_str().unwrap();
    let b = cases[cases.len() - 1]["hex"].as_str().unwrap();
    assert_ne!(a, b, "不同发行方必须产生不同哈希");
}

#[test]
fn domain_control_payload_hash_matches_vectors() {
    let v = vectors();
    let cases = v["domain_control"]
        .as_array()
        .expect("domain_control cases");
    assert!(!cases.is_empty());

    for case in cases {
        let domain = case["domain"].as_str().unwrap();
        let issuer = case["issuer_did"].as_str().unwrap();
        let expected = case["hex"].as_str().unwrap();

        assert_eq!(
            domain_control::payload_hash(domain, issuer).unwrap(),
            expected,
            "case {:?}",
            case["case"]
        );
    }
}

#[test]
fn vectors_cover_the_invariants_this_crate_owns() {
    // N15（事实锚不可替换）与 §7.3（类型标签必须与 preimage 配对）的向量侧保障：
    // 向量文件必须同时含有邮件层分组，说明镜像没被截断；但本 crate 不实现它们。
    let v = vectors();
    for group in [
        "content_v1",
        "rcpt_hash",
        "signing_input",
        "header",
        "payload_hash",
        "domain_control",
        "auth_results",
        "verdict",
        "payload",
    ] {
        assert!(
            v[group].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "vector group `{group}` must exist and be non-empty"
        );
    }
}

#[test]
fn empty_and_newline_inputs_are_rejected_by_both_builders() {
    assert!(email_binding::payload_hash("", "a@b.c", "did:web:i").is_err());
    assert!(email_binding::payload_hash("did:key:z", "", "did:web:i").is_err());
    assert!(email_binding::payload_hash("did:key:z", "a@b.c", "").is_err());
    assert!(email_binding::payload_hash("did:key:z\nx", "a@b.c", "did:web:i").is_err());

    assert!(domain_control::payload_hash("", "did:web:i").is_err());
    assert!(domain_control::payload_hash("example.com", "").is_err());
    assert!(domain_control::payload_hash("example.com\r\nX", "did:web:i").is_err());
}
