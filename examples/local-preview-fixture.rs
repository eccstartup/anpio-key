//! Disposable fixture / independent upstream verifier for local acceptance only.
//! Fixed public test password and reduced KDF parameters: NEVER use real identities.
use std::path::PathBuf;
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some(mode @ ("generate" | "generate-se")) => {
            let path = PathBuf::from(args.next().expect("new fixture directory"));
            assert!(args.next().is_none());
            generate(path, mode == "generate-se");
        }
        Some("verify") => {
            use std::collections::BTreeMap;
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(65_537)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= 65_536);
            let input: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let headers: BTreeMap<String, String> =
                serde_json::from_value(input["headers"].clone()).unwrap();
            anp::authentication::verify_http_message_signature(
                &input["document"],
                "GET",
                input["url"].as_str().unwrap(),
                &headers,
                None,
            )
            .expect("independent upstream verification failed");
            println!("VERIFIED");
        }
        _ => panic!("expected generate/generate-se NEW_DIRECTORY or verify with public JSON stdin"),
    }
}
fn generate(path: PathBuf, secure_enclave: bool) {
    use anpio_key::crypto::kdf::Argon2Config;
    use anpio_key::did::document::{self, DidDocumentSpec};
    use anpio_key::keystore::hardware::HardwareChoice;
    use anpio_key::keystore::layout::KeydLayout;
    use anpio_key::keystore::{create, device, store, unwrap};
    // Only the disposable hot key uses SE. The root remains available for
    // document construction; the independent service must never open SE itself.
    let hot_hardware = if secure_enclave {
        "secure-enclave".parse::<HardwareChoice>()
            .expect("generate-se requires macOS and hardware-se")
    } else {
        HardwareChoice::None
    };
    assert!(!path.exists(), "fixture must be newly generated");
    let layout = KeydLayout::at(path);
    layout.ensure().unwrap();
    let spec = DidDocumentSpec::new("example.com", vec!["boundary-test".into()]);
    let pass = b"temporary-boundary-test-secret";
    let created = create::create(
        &layout,
        &spec,
        "disposable",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
    let key = unwrap::unlock(&wrapped, pass, &device::load(&layout).unwrap()).unwrap();
    let doc = document::publishable(&spec, &created.did, &key).unwrap();
    let (hot, extra) = create::create_extra(
        &layout,
        &created.did,
        "http-hot",
        vec![anp::authentication::DidVerificationRelationship::Authentication],
        "disposable-hot",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        hot_hardware,
    )
    .unwrap();
    let mut unsigned = anpio_key::did::lifecycle::strip_proof(&doc).unwrap();
    unsigned["service"] = serde_json::json!([{"id":format!("{}#anp",created.did),"type":"ANPMessageService","serviceEndpoint":"https://example.com/anp-im/rpc","serviceDid":"did:wba:example.com"}]);
    let unsigned = anpio_key::did::lifecycle::with_extra_key(
        &unsigned,
        &created.did,
        &key.verifying_key().unwrap(),
        extra,
    )
    .unwrap();
    let (_, next) = create::create_extra(
        &layout,
        &created.did,
        "http-next",
        vec![anp::authentication::DidVerificationRelationship::Authentication],
        "disposable-next",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let unsigned = anpio_key::did::lifecycle::with_extra_key(
        &unsigned,
        &created.did,
        &key.verifying_key().unwrap(),
        next,
    )
    .unwrap();
    let doc = document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
    store::write_did_document(&layout, &created.did, &doc).unwrap();
    println!(
        "{}",
        serde_json::json!({"did":created.did,"kid":wrapped.id.kid,"document":doc,
            "hot_kid": hot.id.kid, "hot_hardware": hot.hardware,
            "fixture_only": true, "protected_supported": false})
    );
}
