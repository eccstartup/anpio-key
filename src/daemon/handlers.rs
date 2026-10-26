//! 六类请求的处理。
//!
//! 这一层是"对端说的话"和"守护进程做的事"之间唯一的翻译。它有两个纪律：
//!
//! 1. **每一个出口都是一个 [`Result`]。** 没有任何分支能绕过错误处理直接把
//!    一个成功应答塞回去 —— 一旦有，那条分支就成了唯一没人看过的路径。
//! 2. **拒绝也留痕。** 一次被挡掉的调用在审计里必须留下东西，否则"有人
//!    一直在试"和"什么都没发生"在事后完全一样。
//!
//! 它不认识 socket，也不认识密码学。给它一个已认证的对端和一条请求，
//! 它给回一条应答。所以整个协议面可以不起进程地测。

use crate::audit::Event;
use crate::daemon::peer::PeerIdentity;
use crate::daemon::state::DaemonState;
use crate::daemon::wire::{Request, Response, SignRequest};
use crate::error::{KeydError, Result};
use crate::sign::rfc9421;
use crate::sign::Signer;

/// 处理一条请求。**这个是唯一入口** —— 错误在这里变成应答，不往上冒。
pub fn handle(state: &DaemonState, peer: &PeerIdentity, request: Request) -> Response {
    match dispatch(state, peer, request) {
        Ok(response) => response,
        Err(error) => {
            // 拒绝留痕。写不进去也不改变拒绝本身 —— 但要让守护进程的日志
            // 知道审计掉了链子，因为那时候"留痕"这个承诺已经不成立了。
            if let Err(audit_error) = record_denial(state, peer, &error) {
                tracing::error!(
                    uid = peer.uid,
                    "a refused request could not be recorded in the audit log: {audit_error}"
                );
            }
            Response::from_error(&error)
        }
    }
}

fn dispatch(state: &DaemonState, peer: &PeerIdentity, request: Request) -> Result<Response> {
    match request {
        Request::ListKeys => Ok(Response::ListKeys(state.list_keys(peer.uid)?)),
        Request::Status => Ok(Response::Status(state.status(peer.uid)?)),

        Request::Unlock { did, kid, passphrase } => {
            // 口令从 socket 上传过来，用完就在 daemon 侧擦掉。
            state.unlock(peer.uid, &did, kid.as_deref(), passphrase)?;
            state.record(peer.uid, &Event::Unlocked { uid: peer.uid, did })?;
            Ok(Response::Ok)
        }

        Request::Lock { did, kid } => {
            let dropped = state.lock(peer.uid, did.as_deref(), kid.as_deref())?;
            state.record(
                peer.uid,
                &Event::Locked { uid: peer.uid, did, dropped },
            )?;
            Ok(Response::Ok)
        }

        Request::Sign(request) => sign_request(state, peer, request),

        Request::GetDocument { did } => {
            let (document, digest) = state.get_document(peer.uid, &did)?;
            state.record(
                peer.uid,
                &Event::DocumentRead { uid: peer.uid, did, document_digest: digest },
            )?;
            Ok(Response::Document(document))
        }
    }
}

fn sign_request(
    state: &DaemonState,
    peer: &PeerIdentity,
    request: SignRequest,
) -> Result<Response> {
    match request {
        SignRequest::Structured {
            did,
            kid,
            method,
            target_uri,
            headers,
            body,
            covered,
            nonce,
        } => {
            let signing = rfc9421::SignRequest {
                method,
                // RFC 9421 的 `@target-uri` 就是这条请求的完整 URI。
                url: target_uri,
                headers,
                body,
                covered,
                nonce,
            };

            let signed = state.sign_structured(peer.uid, &did, kid.as_deref(), &signing)?;

            let event = Event::Signed {
                uid: peer.uid,
                did,
                kid: signed
                    .headers
                    .get("Signature-Input")
                    .and_then(|input| kid_from_signature_input(input))
                    .unwrap_or_default(),
                covered: signed.covered.clone(),
                // 摘要，不是签名基本身 —— 基里逐行躺着请求头原文。
                signature_base_digest: crate::audit::log::digest_hex(&signed.signature_base_digest),
            };
            state.record(peer.uid, &event)?;

            // 把签名结果原样交回。`Signature-Input` / `Signature`（以及有
            // body 时的 `Content-Digest`）由上游生成，我们一个字段都不改。
            Ok(Response::Signature(encode_signed_headers(&signed.headers)))
        }

        SignRequest::Raw { did, kid, payload } => {
            let signature =
                state.sign_raw(peer.uid, &did, kid.as_deref(), |key| key.sign(&payload))?;

            let event = Event::RawSigned {
                uid: peer.uid,
                did,
                payload_len: payload.len(),
                payload_digest: crate::audit::log::digest_hex(&payload),
            };
            state.record(peer.uid, &event)?;

            Ok(Response::Signature(signature.to_vec()))
        }

        SignRequest::Challenge { did, kid, challenge } => {
            let signature = state.sign_challenge(peer.uid, &did, kid.as_deref(), |key| {
                key.sign(&challenge)
            })?;

            let event = Event::ChallengeSigned {
                uid: peer.uid,
                did,
                challenge_len: challenge.len(),
                challenge_digest: crate::audit::log::digest_hex(&challenge),
            };
            state.record(peer.uid, &event)?;

            Ok(Response::Signature(signature.to_vec()))
        }
    }
}

/// 把签名完的头发回去。
///
/// 线上就是这几行的原文，一行一个 `名字: 值`。调用方拿去加到自己那条请求
/// 上即可 —— **改动其中任何一个字节，签名就验不过**，所以这里没有"格式化"
/// 的余地，只能原样搬运。
///
/// 用 `\n` 分隔；值里不可能有 `\n`（[`rfc9421`] 在边界上就把带换行的头
/// 值拒掉了），所以这个格式是无歧义的。
fn encode_signed_headers(headers: &std::collections::BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out
}

/// 从 `Signature-Input` 里把 `keyid="..."` 抠出来，只为审计里记一笔。
///
/// **这不是解析器，也不假装是。** 值对我们自己刚生成的那一份来说是好读的；
/// 读不出来就记空字符串 —— 审计少一个字段远好过因为抠不出来而让签名失败。
fn kid_from_signature_input(input: &str) -> Option<String> {
    let rest = input.split_once("keyid=\"")?.1;
    Some(rest.split_once('"')?.0.to_string())
}

/// 一次被拒的调用，记到**服务方自己**的审计目录。
fn record_denial(state: &DaemonState, peer: &PeerIdentity, error: &KeydError) -> Result<()> {
    // 连接层的拒绝（对端身份不认）还没走到 vault 那一步，所以这里写的是
    // 服务方自己的那一份日志 —— 被拒的 uid 的目录我们多半根本写不进去。
    let event = Event::Denied {
        uid: Some(peer.uid),
        pid: peer.pid,
        reason: error.wire_message(),
    };
    state.record_service(&event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;
    use crate::daemon::autolock::Autolock;
    use crate::daemon::state::{Roots, SigningGates};
    use crate::did::DidDocumentSpec;
    use crate::keystore::layout::KeydLayout;
    use crate::keystore::hardware::HardwareChoice;
    use crate::keystore::{create, store};
    use std::collections::BTreeMap;
    use std::time::Duration;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn fast() -> Argon2Config {
        Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    struct Fixture {
        _dir: TempDir,
        state: DaemonState,
        did: String,
    }

    impl Fixture {
        fn new(gates: SigningGates) -> Self {
            let dir = TempDir::new();
            let layout = KeydLayout::at(dir.path().to_path_buf());
            layout.ensure().unwrap();

            let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
                .with_fragment("key-1");
            let created = create::create(
                &layout,
                &spec,
                "default",
                PASSPHRASE.as_bytes(),
                fast(),
                HardwareChoice::None,
            )
            .unwrap();

            // `keygen` 不写 DID 文档(没签名的文档落盘会让人以为它已经发布
            // 了),签名时用的必须是**已发布出去的那一份**。所以这里补上
            // `publish` 的活 —— 补的是签好的,不是随手拼一份。
            let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
            let device_secret = crate::keystore::device::load(&layout).unwrap();
            let key = crate::keystore::unwrap::unlock(
                &wrapped,
                PASSPHRASE.as_bytes(),
                &device_secret,
            )
            .unwrap();
            let document = crate::did::document::publishable(&spec, &created.did, &key).unwrap();
            store::write_did_document(&layout, &created.did, &document).unwrap();
            drop(key);

            Self {
                state: DaemonState::new(
                    Roots::Single(layout),
                    Default::default(),
                    Autolock::idle(Duration::from_secs(900)),
                    gates,
                ),
                did: created.did,
                _dir: dir,
            }
        }

        fn peer(&self) -> PeerIdentity {
            PeerIdentity { uid: 501, gid: 20, pid: Some(1234) }
        }

        fn unlock(&self) -> Response {
            handle(
                &self.state,
                &self.peer(),
                Request::Unlock {
                    did: self.did.clone(),
                    kid: None,
                    passphrase: zeroize::Zeroizing::new(PASSPHRASE.to_string()),
                },
            )
        }

        fn structured(&self) -> Request {
            let mut headers = BTreeMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            Request::Sign(SignRequest::Structured {
                did: self.did.clone(),
                kid: None,
                method: "POST".into(),
                target_uri: "https://example.com/api".into(),
                headers,
                body: Some(b"{}".to_vec()),
                covered: Vec::new(),
                nonce: None,
            })
        }

        fn audit_text(&self) -> String {
            let dir = self.state.layout_for(501).unwrap().audit_dir();
            let mut out = String::new();
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|e| e == "jsonl") {
                    out.push_str(&std::fs::read_to_string(&path).unwrap());
                }
            }
            out
        }
    }

    #[test]
    fn listing_and_status_work_without_unlocking() {
        let f = Fixture::new(SigningGates::new(false, false));
        let Response::ListKeys(keys) = handle(&f.state, &f.peer(), Request::ListKeys) else {
            panic!("expected a key list");
        };
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].did, f.did);

        let Response::Status(keys) = handle(&f.state, &f.peer(), Request::Status) else {
            panic!("expected a status");
        };
        assert!(keys.is_empty());
    }

    #[test]
    fn unlocking_then_signing_returns_the_signature_headers() {
        let f = Fixture::new(SigningGates::new(false, false));
        assert_eq!(f.unlock(), Response::Ok);

        let Response::Signature(bytes) = handle(&f.state, &f.peer(), f.structured()) else {
            panic!("expected a signature");
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Signature-Input: "), "{text}");
        assert!(text.contains("Signature: "), "{text}");
        // 有 body，就有 content-digest —— 而且它是守护进程自己算的。
        assert!(text.contains("Content-Digest: "), "{text}");
    }

    /// 签名头必须是**逐字节**可用的原文：中间多一个空格，签名就验不过。
    #[test]
    fn the_headers_come_back_exactly_as_the_upstream_built_them() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let Response::Signature(bytes) = handle(&f.state, &f.peer(), f.structured()) else {
            panic!("expected a signature");
        };

        let text = String::from_utf8(bytes).unwrap();
        for line in text.lines() {
            let (name, value) = line.split_once(": ").expect("every line is 'name: value'");
            assert!(!name.is_empty());
            assert!(!value.is_empty());
            assert!(!value.contains('\n'));
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn signing_a_locked_key_answers_locked_and_says_nothing_else() {
        let f = Fixture::new(SigningGates::new(false, false));
        assert_eq!(
            handle(&f.state, &f.peer(), f.structured()),
            Response::Error {
                code: crate::daemon::wire::ErrorCode::Locked,
                message: "key is locked".into(),
            }
        );
    }

    /// **拒绝也要留痕。** 一次被挡掉的签名在审计里必须看得见。
    #[test]
    fn a_refused_signature_is_still_written_to_the_audit_log() {
        let f = Fixture::new(SigningGates::new(false, false));
        assert!(f.audit_text().is_empty(), "nothing should be logged yet");

        let _ = handle(&f.state, &f.peer(), f.structured());

        let text = f.audit_text();
        assert!(text.contains("DENIED"), "{text}");
        assert!(text.contains("key is locked"), "{text}");
        // 拒绝的那条也进链，链照样是完整的一串。
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn a_successful_signature_is_logged_with_the_base_digest() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();
        let _ = handle(&f.state, &f.peer(), f.structured());

        let text = f.audit_text();
        assert!(text.contains("UNLOCKED"), "{text}");
        assert!(text.contains("SIGNED"), "{text}");
        assert!(text.contains("signature_base_digest"), "{text}");
        assert!(text.contains("@target-uri"), "{text}");

        // 签名基本身不进去 —— 它逐行带着请求头原文。
        assert!(!text.contains("@target-uri\": https://"), "the base leaked: {text}");
    }

    #[test]
    fn locking_is_logged_and_drops_the_key() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();
        assert_eq!(
            handle(&f.state, &f.peer(), Request::Lock { did: Some(f.did.clone()), kid: None }),
            Response::Ok
        );

        let Response::Status(keys) = handle(&f.state, &f.peer(), Request::Status) else {
            panic!("expected a status");
        };
        assert!(keys.is_empty());
        assert!(f.audit_text().contains("LOCKED"));

        // 锁上之后再签就是锁着。
        let Response::Error { code, .. } = handle(&f.state, &f.peer(), f.structured()) else {
            panic!("expected a refusal");
        };
        assert_eq!(code, crate::daemon::wire::ErrorCode::Locked);
    }

    #[test]
    fn raw_signing_is_refused_while_the_switch_is_off_and_says_why() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let Response::Error { code, message } = handle(
            &f.state,
            &f.peer(),
            Request::Sign(SignRequest::Raw {
                kid: None,
                did: f.did.clone(),
                payload: b"anything".to_vec(),
            }),
        ) else {
            panic!("expected a refusal");
        };

        // 拒绝的原因是**说得出**的：这条路默认关着，怎么开也在消息里。
        // 和口令类错误不一样 —— 那一类必须含糊，这一类含糊只会让人查不动。
        assert_eq!(code, crate::daemon::wire::ErrorCode::RawDisabled);
        assert!(message.contains("--allow-raw-signing"), "{message}");
    }

    #[test]
    fn raw_signing_works_when_the_operator_turned_it_on() {
        let f = Fixture::new(SigningGates::new(true, false));
        f.unlock();

        let Response::Signature(signature) = handle(
            &f.state,
            &f.peer(),
            Request::Sign(SignRequest::Raw {
                kid: None,
                did: f.did.clone(),
                payload: b"anything".to_vec(),
            }),
        ) else {
            panic!("expected a signature");
        };

        assert_eq!(signature.len(), 64);
        // 而且它留痕了，带的是载荷的摘要而不是载荷。
        let text = f.audit_text();
        assert!(text.contains("RAW_SIGNED"), "{text}");
        assert!(!text.contains("anything"), "the payload leaked into the log: {text}");
    }

    /// 挑战签名这条路默认也关着，而且拒的时候**说得清是哪个开关** ——
    /// 和 raw 那条一样，含糊在这里只会让人查不动。
    #[test]
    fn challenge_signing_is_refused_while_the_switch_is_off_and_says_why() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let Response::Error { code, message } = handle(
            &f.state,
            &f.peer(),
            Request::Sign(SignRequest::Challenge {
                kid: None,
                did: f.did.clone(),
                challenge: b"server-issued".to_vec(),
            }),
        ) else {
            panic!("expected a refusal");
        };

        assert_eq!(code, crate::daemon::wire::ErrorCode::ChallengeDisabled);
        assert!(message.contains("--allow-challenge-signing"), "{message}");
    }

    /// 打开之后它回的是一次真签名，并且只把**摘要**记进审计 —— 挑战原文
    /// 不该落进那个会被备份走的文件里，和 [`Event::RawSigned`] 同一个道理。
    #[test]
    fn document_proof_input_fits_legacy_challenge_but_is_denied_by_default() {
        // Use the actual upstream proof builder, not a guessed 64-byte payload.
        for enabled in [false, true] {
            let f = Fixture::new(SigningGates::new(false, enabled));
            assert_eq!(f.unlock(), Response::Ok);
            let layout = f.state.layout_for(f.peer().uid).unwrap();
            let wrapped = store::load_all(&layout).unwrap().remove(0);
            let device = crate::keystore::device::load(&layout).unwrap();
            let key = crate::keystore::unwrap::unlock(&wrapped, PASSPHRASE.as_bytes(), &device).unwrap();
            let document = crate::did::document::rebuild(&f.did, &key.verifying_key()).unwrap();
            let prepared = anp::proof::prepare_w3c_proof(
                &document, &key.anp_public_key(), &wrapped.id.kid,
                anp::proof::ProofGenerationOptions {
                    proof_purpose: Some("assertionMethod".into()),
                    proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.into()),
                    cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.into()),
                    created: None, domain: None, challenge: None,
                },
            ).unwrap();
            assert_eq!(prepared.signing_input().len(), 64);
            assert!(prepared.signing_input().len() <= crate::daemon::wire::MAX_CHALLENGE_LEN);
            let response = handle(&f.state, &f.peer(), Request::Sign(SignRequest::Challenge {
                did: f.did.clone(), kid: None, challenge: prepared.signing_input().to_vec(),
            }));
            if enabled {
                // Explicit development compatibility still signs a valid document proof.
                let Response::Signature(signature) = response else { panic!("{response:?}") };
                let signed = anp::proof::complete_w3c_proof(prepared, &signature).unwrap();
                assert!(anp::authentication::validate_did_document_binding(&signed, true));
            } else {
                let Response::Error { code, .. } = response else { panic!("{response:?}") };
                assert_eq!(code, crate::daemon::wire::ErrorCode::ChallengeDisabled);
            }
        }
    }

    #[test]
    fn challenge_signing_signs_the_challenge_bytes_when_on() {
        let f = Fixture::new(SigningGates::new(false, true));
        f.unlock();

        let challenge = b"register-now-please".to_vec();
        let Response::Signature(signature) = handle(
            &f.state,
            &f.peer(),
            Request::Sign(SignRequest::Challenge {
                kid: None,
                did: f.did.clone(),
                challenge: challenge.clone(),
            }),
        ) else {
            panic!("expected a signature");
        };

        assert_eq!(signature.len(), 64);
        // 留痕带的是挑战的**摘要**，不是挑战本身。
        let text = f.audit_text();
        assert!(text.contains("CHALLENGE_SIGNED"), "{text}");
        assert!(text.contains("challenge_digest"), "{text}");
        assert!(
            !text.contains("register-now-please"),
            "the challenge leaked into the log: {text}"
        );
    }

    #[test]
    fn the_wrong_passphrase_answers_the_same_thing_a_missing_device_secret_would() {
        let f = Fixture::new(SigningGates::new(false, false));
        let Response::Error { code, message } = handle(
            &f.state,
            &f.peer(),
            Request::Unlock {
                kid: None,
                did: f.did.clone(),
                passphrase: zeroize::Zeroizing::new("wrong".into()),
            },
        ) else {
            panic!("expected a refusal");
        };

        assert_eq!(code, crate::daemon::wire::ErrorCode::BadCredential);
        assert_eq!(message, "the credential was refused");
    }

    #[test]
    fn asking_for_an_unknown_key_answers_key_not_found() {
        let f = Fixture::new(SigningGates::new(false, false));
        let Response::Error { code, .. } = handle(
            &f.state,
            &f.peer(),
            Request::Unlock {
                kid: None,
                did: "did:wba:example.com:user:bob:e1_zzz".into(),
                passphrase: zeroize::Zeroizing::new(PASSPHRASE.into()),
            },
        ) else {
            panic!("expected a refusal");
        };
        assert_eq!(code, crate::daemon::wire::ErrorCode::KeyNotFound);
    }

    /// 请求里要求覆盖一个请求中并不存在的头 —— 这是调用方的错，得说清楚。
    #[test]
    fn a_caller_asking_to_cover_a_header_it_did_not_send_is_refused() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let Request::Sign(SignRequest::Structured {
            did,
            method,
            target_uri,
            headers,
            body,
            ..
        }) = f.structured()
        else {
            unreachable!()
        };
        let request = Request::Sign(SignRequest::Structured {
            did,
            kid: None,
            method,
            target_uri,
            headers,
            body,
            covered: vec!["x-not-sent".into()],
            nonce: None,
        });

        let Response::Error { code, .. } = handle(&f.state, &f.peer(), request) else {
            panic!("expected a refusal");
        };
        assert_eq!(code, crate::daemon::wire::ErrorCode::CoveredSetRejected);
    }

    /// **读文档不需要解锁。** 它是一份可公开的成品,躺在 0644 的文件里;
    /// 拿"没解锁"去挡它,挡掉的只是调用方本来就够得着的东西。
    #[test]
    fn the_document_is_served_byte_for_byte_without_unlocking() {
        let f = Fixture::new(SigningGates::new(false, false));

        let Response::Document(bytes) =
            handle(&f.state, &f.peer(), Request::GetDocument { did: f.did.clone() })
        else {
            panic!("expected a document");
        };

        // 给的必须是**发布出去的那一份**的原文,不是重新序列化出来的。
        let on_disk = std::fs::read(
            f.state.layout_for(501).unwrap().did_path(&f.did),
        )
        .unwrap();
        assert_eq!(bytes, on_disk);

        // 而它确实是一份能解析的文档。
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["id"], f.did);

        // 留痕留的是"谁取走了哪一版",不是"谁被授权了"。
        let text = f.audit_text();
        assert!(text.contains("DOCUMENT_READ"), "{text}");
        assert!(text.contains("document_digest"), "{text}");
    }

    /// 别人的 DID:**答不出来**。守护进程不联网,它替不了调用方去 resolve。
    #[test]
    fn a_did_this_machine_never_published_is_key_not_found() {
        let f = Fixture::new(SigningGates::new(false, false));

        let Response::Error { code, .. } = handle(
            &f.state,
            &f.peer(),
            Request::GetDocument { did: "did:wba:example.com:user:bob:e1_zzz".into() },
        ) else {
            panic!("expected a refusal");
        };
        assert_eq!(code, crate::daemon::wire::ErrorCode::KeyNotFound);
    }

    /// 调用方指定的 nonce 必须落到签名里 —— 它是"同一条请求"和"另一条
    /// 请求"的分界,也是 `@signature-params` 里那个 nonce。
    #[test]
    fn a_caller_supplied_nonce_reaches_the_signature() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let Request::Sign(SignRequest::Structured {
            did,
            method,
            target_uri,
            headers,
            body,
            ..
        }) = f.structured()
        else {
            unreachable!()
        };
        let request = Request::Sign(SignRequest::Structured {
            did,
            kid: None,
            method,
            target_uri,
            headers,
            body,
            covered: Vec::new(),
            nonce: Some("caller-chosen-42".into()),
        });

        let Response::Signature(bytes) = handle(&f.state, &f.peer(), request) else {
            panic!("expected a signature");
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("nonce=\"caller-chosen-42\""), "{text}");
    }

    /// 审计里的 keyid 是从我们自己刚生成的 `Signature-Input` 里读的。
    #[test]
    fn the_logged_kid_comes_from_the_signature_input_we_produced() {
        assert_eq!(
            kid_from_signature_input(
                r#"sig1=("@method" "@target-uri");created=1;keyid="did:wba:x#key-1";alg="ed25519""#
            ),
            Some("did:wba:x#key-1".to_string())
        );
        // 读不出来就记空的 —— 别因为审计字段抠不出来就让签名失败。
        assert_eq!(kid_from_signature_input("@signature-params"), None);
    }

    mod tempdir {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "anpio-key-handlers-{}-{n}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    use tempdir::TempDir;
}
