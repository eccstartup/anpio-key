//! 签名路径的吞吐基线。
//!
//! 只量**签名核心**:输入校验 + 规范化 + 拼基 + Ed25519。socket 往返、主体
//! 查询、SQLite 预留/提交都不在这里 —— 那几项的代价要一台跑着守护进程的
//! 机器,用 `deploy/linux/` 的验收驱动量。这里的数回答的是"签名本身贵不贵",
//! 用来判断 P1 之前要不要动连接模型。
//!
//! 跑法:`cargo bench --bench sign_throughput`(release 构建,否则数字没有意义)。

use std::collections::BTreeMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anpio_key::crypto::hygiene::LockedBytes;
use anpio_key::did::{build_unsigned, sign_document, DidDocumentSpec};
use anpio_key::keystore::record::KeyId;
use anpio_key::persistence::clock::Time;
use anpio_key::security::http::{Body, CanonicalHttpRequest, HttpRequest};
use anpio_key::sign::LockedSigningKey;

const ITERATIONS: usize = 2_000;
const WARMUP: usize = 100;

fn key(seed_byte: u8) -> LockedSigningKey {
    let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
    let placeholder = KeyId {
        did: String::new(),
        kid: String::new(),
        thumbprint: String::new(),
    };
    LockedSigningKey::from_seed(placeholder, seed).unwrap()
}

/// 一把钥匙、它的公开文档、以及文档未签名的那一半。
fn fixture(seed_byte: u8) -> (LockedSigningKey, serde_json::Value, serde_json::Value) {
    let bare = key(seed_byte);
    let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()]);
    let (did, unsigned) = build_unsigned(&spec, &bare.verifying_key()).unwrap();
    let signed = sign_document(&unsigned, &bare, &format!("{did}#key-1")).unwrap();
    let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
    let key = LockedSigningKey::from_seed(
        KeyId {
            did: did.clone(),
            kid: format!("{did}#key-1"),
            thumbprint: did.rsplit(':').next().unwrap().to_string(),
        },
        seed,
    )
    .unwrap();
    (key, signed, unsigned)
}

fn http_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: "https://service.example.com/v1/messages".into(),
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
        body: Body::Present {
            bytes: br#"{"text":"hello"}"#.to_vec(),
        },
        nonce: Some("0123456789abcdef".into()),
    }
}

fn measure(label: &str, mut op: impl FnMut()) {
    for _ in 0..WARMUP {
        op();
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        op();
    }
    let elapsed = start.elapsed().as_secs_f64();
    let per_op = elapsed / ITERATIONS as f64;
    println!(
        "{label:<32}{:>9.2} µs/op{:>12.0} op/s",
        per_op * 1e6,
        1.0 / per_op
    );
}

fn main() {
    let (key, document, unsigned) = fixture(7);
    let kid = key.id().kid.clone();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let clock = Time {
        wall: now,
        monotonic_ms: 1_000,
    };
    let canonical = CanonicalHttpRequest::new(http_request()).unwrap();

    println!("anpio-key signing core, {ITERATIONS} iterations\n");
    measure("canonicalize http request", || {
        CanonicalHttpRequest::new(http_request()).unwrap();
    });
    measure("sign_http (canonical + ed25519)", || {
        canonical
            .sign_profile(&document, &key, clock, now + 300, 301_000)
            .unwrap();
    });
    measure("document_proof (ed25519)", || {
        sign_document(&unsigned, &key, &kid).unwrap();
    });
    println!(
        "\nPer-message cost of the daemon's signing core. Add socket round trip,\n\
         principal lookup and the SQLite reserve/complete transactions on top;\n\
         those need a live service and are measured by deploy/linux acceptance."
    );
}
