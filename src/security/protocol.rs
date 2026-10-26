//! Versioned, bounded JSON protocol. Data requests have no password operation.
use crate::error::{KeydError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const VERSION: u32 = 2;
pub const MAX_FRAME: usize = 65_536;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub version: u32,
    pub request: T,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum DataRequest {
    #[serde(rename = "GET_CAPABILITIES")]
    Capabilities {},
    #[serde(rename = "LIST_AUTHORIZED_KEYS")]
    ListAuthorizedKeys {},
    #[serde(rename = "GET_GRANT_STATUS")]
    GrantStatus { grant_id: String },
    #[serde(rename = "GET_DOCUMENT")]
    Document { key_id: String },
    #[serde(rename = "SIGN_HTTP")]
    SignHttp {
        grant_id: String,
        request_id: String,
        http: super::http::HttpRequest,
    },
    /// ANP origin proof。`origin` 是事实,签名基由 daemon 拼。
    #[serde(rename = "SIGN_ORIGIN_PROOF")]
    SignOriginProof {
        grant_id: String,
        request_id: String,
        origin: super::origin::OriginProofRequest,
    },
    /// 绑定用途的断言签名。键由 purpose 决定,调用方给不了 key 相关字段。
    #[serde(rename = "SIGN_PURPOSE")]
    SignPurpose {
        grant_id: String,
        request_id: String,
        /// `device_assertion` 或 `application_assertion`;必须和键上绑定的一致。
        purpose: String,
        /// 只有 `application_assertion` 给,其余给了就是非法。
        #[serde(default)]
        domain: Option<String>,
        /// 小写 hex,≤4096 字节。
        payload: String,
    },
    /// 对象 proof。daemon 用设备签名键给一个任意 JSON 对象盖上
    /// `assertionMethod` 的 DataIntegrityProof;键由 grant 决定。
    #[serde(rename = "SIGN_OBJECT_PROOF")]
    SignObjectProof {
        grant_id: String,
        request_id: String,
        /// 待签对象。顶层 `proof` 会被摘掉,不参与签名。
        object: serde_json::Value,
    },
    /// 文档 proof。签的是**整份**属于这把键的 DID 文档,不是随便一份 JSON。
    #[serde(rename = "SIGN_DOCUMENT_PROOF")]
    SignDocumentProof {
        grant_id: String,
        request_id: String,
        /// 完整文档。`id` 必须是这把键的 DID,而键必须还挂在文档里。
        document: serde_json::Value,
        /// `assertionMethod`(缺省)或 `authentication`。
        #[serde(default)]
        proof_purpose: Option<String>,
        #[serde(default)]
        domain: Option<String>,
        #[serde(default)]
        challenge: Option<String>,
    },
    /// X25519 协商。`peer` 是 32 字节公钥的小写 hex;共享密钥只回一次,不落库。
    #[serde(rename = "ECDH")]
    Ecdh {
        grant_id: String,
        request_id: String,
        peer: String,
    },
    /// 长生命周期 grant 续期。只能往上顶到策略给的天花板。
    #[serde(rename = "RENEW_GRANT")]
    RenewGrant { grant_id: String, expiry: i64 },
    #[serde(rename = "GET_REQUEST_STATUS")]
    RequestStatus { request_id: String },
}

// Deliberately no Debug implementation: even malformed admin inputs are secret.
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum AdminRequest {
    #[serde(rename = "START_SE_SESSION")]
    StartSeSession {
        vault_id: String,
        did: String,
        kid: String,
    },
    #[serde(rename = "COMPLETE_SECRET_OPERATION")]
    CompleteSecretOperation {
        operation_id: String,
        digest: String,
    },
    #[serde(rename = "GET_CAPABILITIES")]
    Capabilities {},
    #[serde(rename = "LIST_PRINCIPALS")]
    ListPrincipals {},
    #[serde(rename = "GET_CATALOG")]
    Catalog {},
    #[serde(rename = "PREPARE_OPERATION")]
    Prepare { change: crate::persistence::Change },
    #[serde(rename = "COMMIT_OPERATION")]
    Commit {
        operation_id: String,
        digest: String,
    },
    #[serde(rename = "LOCK_ALL")]
    LockAll {},
    #[serde(rename = "UNLOCK_KEY")]
    Unlock {
        vault_id: String,
        did: String,
        kid: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SeHeartbeat {
    pub session_id: String,
    pub sequence: u64,
}

pub(crate) fn read_hs(reader: &mut impl Read) -> Result<crate::crypto::hygiene::LockedBytes> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    reader.read_exact(&mut *bytes)?;
    crate::crypto::hygiene::LockedBytes::new(&mut bytes)
}

pub(crate) fn write_hs(
    writer: &mut impl Write,
    hs: &crate::crypto::hygiene::LockedBytes,
) -> Result<()> {
    hs.expose(|bytes| writer.write_all(bytes))?;
    writer.flush()?;
    Ok(())
}

// Passwords occupy a separate bounded binary frame, only after an authenticated
// management UNLOCK_KEY header. JSON escape/parser scratch buffers never see them.
pub fn read_secret<R: Read>(reader: &mut R) -> Result<Zeroizing<String>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(KeydError::Protocol("invalid credential frame size".into()));
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| KeydError::Protocol("invalid credential encoding".into()))?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn write_secret<W: Write>(writer: &mut W, secret: &str) -> Result<()> {
    if secret.is_empty() || secret.len() > MAX_FRAME {
        return Err(KeydError::Protocol("invalid credential frame size".into()));
    }
    writer.write_all(&(secret.len() as u32).to_be_bytes())?;
    writer.write_all(secret.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u32,
    pub code: String,
    pub instance_id: Option<String>,
    pub principal_id: Option<String>,
    pub signing_available: bool,
    pub protected_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared: Option<crate::persistence::Prepared>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<crate::principal::Principal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<crate::persistence::catalog::Catalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
impl Reply {
    pub fn code(code: &str) -> Self {
        Self {
            version: VERSION,
            code: code.into(),
            instance_id: None,
            principal_id: None,
            signing_available: false,
            protected_supported: false,
            prepared: None,
            boot_epoch: None,
            principals: None,
            catalog: None,
            data: None,
        }
    }
}

pub fn read<R: Read, T: serde::de::DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(KeydError::Protocol("invalid protected frame size".into()));
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes)?;
    // serde error messages can contain attacker supplied values, including passwords.
    super::json::decode(&bytes)
}

pub fn write<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    // Fixed capacity avoids leaving prior allocations of plaintext after realloc.
    let mut bytes = Zeroizing::new(vec![0; MAX_FRAME]);
    let mut buffer = std::io::Cursor::new(&mut bytes[..]);
    serde_json::to_writer(&mut buffer, value).map_err(|_| {
        KeydError::Protocol("protected frame exceeds limit or cannot be encoded".into())
    })?;
    let len = buffer.position() as usize;
    writer.write_all(&(len as u32).to_be_bytes())?;
    writer.write_all(&bytes[..len])?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
        let mut frame = (text.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(text.as_bytes());
        read(&mut &frame[..])
    }
    #[test]
    fn binary_secret_round_trips_arbitrary_utf8_without_json_escaping() {
        let password = Zeroizing::new("spaces \" \\ \n \0 密码".to_string());
        let mut frame = Zeroizing::new(Vec::new());
        write_secret(&mut *frame, &password).unwrap();
        assert_eq!(*read_secret(&mut &frame[..]).unwrap(), *password);
        assert!(read_secret(&mut &[0, 0, 0, 0][..]).is_err());
        assert!(read_secret(&mut &[0, 0, 0, 2, 0xff, 0xff][..]).is_err());
        assert!(read::<_, Envelope<DataRequest>>(&mut &(u32::MAX.to_be_bytes())[..]).is_err());
    }

    #[test]
    fn data_rejects_password_operations_duplicates_unknown_fields_and_v1() {
        for request in [
            r#"{"version":2,"request":{"operation":"START_SE_SESSION","vault_id":"v","did":"d","kid":"k"}}"#,
            r#"{"version":2,"request":{"operation":"UNLOCK_KEY","passphrase":"secret"}}"#,
            r#"{"version":2,"version":2,"request":{"operation":"GET_CAPABILITIES"}}"#,
            r#"{"version":2,"request":{"operation":"GET_CAPABILITIES","passphrase":"secret"}}"#,
            r#"{"version":4294967296,"request":{"operation":"GET_CAPABILITIES"}}"#,
        ] {
            let error = parse::<Envelope<DataRequest>>(request).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        assert!(read::<_, Envelope<DataRequest>>(&mut &[0, 0, 0, 1, 3][..]).is_err());
    }

    #[test]
    fn se_secret_frame_is_fixed_size_and_not_a_json_credential() {
        let hs = crate::crypto::hygiene::LockedBytes::fill(|bytes| *bytes = [29; 32]).unwrap();
        let mut frame = Zeroizing::new(Vec::new());
        write_hs(&mut *frame, &hs).unwrap();
        assert_eq!(frame.len(), 32);
        read_hs(&mut &frame[..])
            .unwrap()
            .expose(|bytes| assert_eq!(*bytes, [29; 32]));
        assert!(read_hs(&mut &frame[..31]).is_err());
        assert!(parse::<Envelope<AdminRequest>>(r#"{"version":2,"request":{"operation":"START_SE_SESSION","vault_id":"v","did":"d","kid":"k","hs":"secret"}}"#).is_err());
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    #[test]
    fn structured_data_requires_body_state_and_forbids_key_or_profile_override() {
        let base = serde_json::json!({"version":2,"request":{"operation":"SIGN_HTTP","grant_id":"g","request_id":"r","http":{"method":"POST","url":"https://example.com/x","headers":{},"body":{"state":"present","bytes":[]},"nonce":null}}});
        let decode = |v: &serde_json::Value| {
            let payload = serde_json::to_vec(v).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            read::<_, Envelope<DataRequest>>(&mut &frame[..])
        };
        assert!(decode(&base).is_ok());
        for field in [
            "did",
            "kid",
            "key_id",
            "covered",
            "passphrase",
            "signature_profile",
        ] {
            let mut bad = base.clone();
            bad["request"][field] = serde_json::json!("override");
            assert!(decode(&bad).is_err(), "{field}");
        }
        let mut bad = base.clone();
        bad["request"]["http"]
            .as_object_mut()
            .unwrap()
            .remove("body");
        assert!(decode(&bad).is_err());
        let mut bad = base.clone();
        bad["request"]["http"]["body"] = serde_json::json!({"state":"absent","bytes":[]});
        assert!(decode(&bad).is_err());
        let mut bad = base.clone();
        bad["request"]["http"]["body"]["bytes"] = serde_json::json!([256]);
        assert!(decode(&bad).is_err());
    }

    /// origin proof 的线上形状就是事实本身:方法、meta、body、可选的 expires/nonce。
    /// 密钥、did、kid 一律不给 —— 那些来自 grant。
    #[test]
    fn origin_proof_takes_facts_only_and_rejects_key_overrides() {
        let base = serde_json::json!({"version":2,"request":{"operation":"SIGN_ORIGIN_PROOF","grant_id":"g","request_id":"r","origin":{
            "method":"direct.send",
            "meta":{"profile":"anp.direct.base.v1","target":{"kind":"agent","did":"did:wba:example.com:bob"}},
            "body":{"text":"hi"}}}});
        let decode = |v: &serde_json::Value| {
            let payload = serde_json::to_vec(v).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            read::<_, Envelope<DataRequest>>(&mut &frame[..])
        };
        assert!(matches!(
            decode(&base).unwrap().request,
            DataRequest::SignOriginProof { .. }
        ));
        for field in ["did", "kid", "key_id", "signature_profile", "passphrase"] {
            let mut bad = base.clone();
            bad["request"]["origin"][field] = serde_json::json!("override");
            assert!(decode(&bad).is_err(), "{field}");
        }
        let mut bad = base.clone();
        bad["request"]["origin"]
            .as_object_mut()
            .unwrap()
            .remove("body");
        assert!(decode(&bad).is_err());
        let renew = serde_json::json!({"version":2,"request":{"operation":"RENEW_GRANT","grant_id":"g","expiry":1000}});
        assert!(matches!(
            decode(&renew).unwrap().request,
            DataRequest::RenewGrant { expiry: 1000, .. }
        ));
    }

    /// purpose 签名是扁平的:用途、可选的域、hex payload。没有域之外的嵌套,
    /// 也就没有地方夹带密钥或公钥。
    #[test]
    fn purpose_signing_takes_a_tag_and_payload_only() {
        let base = serde_json::json!({"version":2,"request":{"operation":"SIGN_PURPOSE",
            "grant_id":"g","request_id":"r","purpose":"device_assertion","payload":"00ff"}});
        let decode = |v: &serde_json::Value| {
            let payload = serde_json::to_vec(v).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            read::<_, Envelope<DataRequest>>(&mut &frame[..])
        };
        assert!(matches!(
            decode(&base).unwrap().request,
            DataRequest::SignPurpose { domain: None, .. }
        ));
        let mut with_domain = base.clone();
        with_domain["request"]["purpose"] = serde_json::json!("application_assertion");
        with_domain["request"]["domain"] = serde_json::json!("chat.alpha");
        assert!(matches!(
            decode(&with_domain).unwrap().request,
            DataRequest::SignPurpose {
                domain: Some(_),
                ..
            }
        ));
        for field in ["did", "kid", "key_id", "payload_digest", "passphrase"] {
            let mut bad = base.clone();
            bad["request"][field] = serde_json::json!("override");
            assert!(decode(&bad).is_err(), "{field}");
        }
        let mut bad = base.clone();
        bad["request"].as_object_mut().unwrap().remove("payload");
        assert!(decode(&bad).is_err());
    }

    /// ECDH 只收一把 peer 公钥。没有 did/kid,也没有第二把钥匙的余地 ——
    /// 用哪把协商键由 grant 决定。
    #[test]
    fn ecdh_takes_one_peer_key_and_nothing_else() {
        let base = serde_json::json!({"version":2,"request":{"operation":"ECDH","grant_id":"g","request_id":"r","peer":format!("{:064x}", 0x11)}});
        let decode = |v: &serde_json::Value| {
            let payload = serde_json::to_vec(v).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            read::<_, Envelope<DataRequest>>(&mut &frame[..])
        };
        assert!(matches!(
            decode(&base).unwrap().request,
            DataRequest::Ecdh { .. }
        ));
        for field in ["did", "kid", "key_id", "public_multibase"] {
            let mut bad = base.clone();
            bad["request"][field] = serde_json::json!("override");
            assert!(decode(&bad).is_err(), "{field}");
        }
        let mut bad = base.clone();
        bad["request"].as_object_mut().unwrap().remove("peer");
        assert!(decode(&bad).is_err());
    }
}
