//! 绑定用途的断言签名(P2):一个 purpose 一把专用键,签调用方给的字节。
//!
//! 和 origin proof 的区别:这里没有可拼的签名基,签的就是 payload 本身;
//! 由 daemon 加的只有上游 `anp_identity` 为 `application_assertion` 定义的
//! 那段域前缀(`payload_for_purpose`)。前缀必须逐字节一致,否则 awiki 侧
//! 验签会失败 —— 它是冻结的格式身份,不是这里能改的实现细节。
//!
//! `authentication` 不在这个面上:请求签名走 `SIGN_HTTP` / `SIGN_ORIGIN_PROOF`,
//! 那两条路有自己的规范化基和策略。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 断言 payload 上限。帧 64 KiB,hex 编码翻一倍,留足信封余量。
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// 上游 `anp_identity` 的域长度上限。
pub const MAX_DOMAIN_BYTES: usize = 256;
const APPLICATION_ASSERTION_PREFIX: &[u8] = b"anp.identity.application-assertion.v1\0";
const DIGEST_DOMAIN: &[u8] = b"anp.sign-purpose.v1\0";

fn invalid() -> KeydError {
    KeydError::Misuse("PURPOSE_INVALID".into())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPurpose {
    DeviceAssertion,
    ApplicationAssertion,
}

impl SigningPurpose {
    /// 所有 purpose 的固定顺序。能力协商和启动审计都按这个顺序列。
    pub const ALL: [Self; 2] = [Self::DeviceAssertion, Self::ApplicationAssertion];

    /// 线上字符串。和 catalog 里 `keys.purpose` 用的是同一组名字。
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "device_assertion" => Ok(Self::DeviceAssertion),
            "application_assertion" => Ok(Self::ApplicationAssertion),
            _ => Err(invalid()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::DeviceAssertion => "device_assertion",
            Self::ApplicationAssertion => "application_assertion",
        }
    }

    fn needs_domain(self) -> bool {
        matches!(self, Self::ApplicationAssertion)
    }
}

/// 校验过的一次断言请求:用途、域和真正要签的字节都已经定下来。
#[derive(Debug, Clone)]
pub struct PurposeRequest {
    purpose: SigningPurpose,
    domain: Option<String>,
    payload: Vec<u8>,
    message: Vec<u8>,
}

/// 一次断言的签名结果。签名是 hex,公钥是 multibase —— 都不含私钥材料。
#[derive(Debug, Clone, Serialize)]
pub struct SignedPurpose {
    pub signature: String,
    pub public_multibase: String,
    pub purpose: Value,
}

impl PurposeRequest {
    /// 线上形状:`payload` 是小写 hex,`domain` 只有 `application_assertion` 给。
    pub fn from_wire(purpose: &str, domain: Option<String>, payload: &str) -> Result<Self> {
        Self::new(
            SigningPurpose::parse(purpose)?,
            domain,
            &decode_hex(payload)?,
        )
    }

    pub fn new(purpose: SigningPurpose, domain: Option<String>, payload: &[u8]) -> Result<Self> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid());
        }
        let (domain, message) = match (purpose.needs_domain(), domain) {
            (false, None) => (None, payload.to_vec()),
            (false, Some(_)) | (true, None) => return Err(invalid()),
            (true, Some(domain)) => {
                validate_domain(&domain)?;
                let message = application_message(&domain, payload);
                (Some(domain), message)
            }
        };
        Ok(Self {
            purpose,
            domain,
            payload: payload.to_vec(),
            message,
        })
    }

    pub fn purpose(&self) -> SigningPurpose {
        self.purpose
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// 去重用的输入摘要。按用途分域:同一个 request_id 换个 purpose 重放会撞
    /// `REQUEST_ID_CONFLICT`,而不是命中这里的缓存。
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.purpose.name().as_bytes());
        hasher.update([0]);
        if let Some(domain) = &self.domain {
            hasher.update(domain.as_bytes());
            hasher.update([0]);
        }
        hasher.update(&self.message);
        hex_of(&hasher.finalize())
    }

    /// 回给调用方的用途标签,形状和上游 `SigningPurpose` 的序列化一致。
    pub fn tag(&self) -> Value {
        match &self.domain {
            Some(domain) => json!({"purpose":self.purpose.name(),"domain":domain}),
            None => json!({"purpose":self.purpose.name()}),
        }
    }

    /// 审计里记的那几个字段。只记摘要和长度,永不记 payload 本身。
    pub fn audit_options(&self) -> Value {
        json!({
            "purpose": self.purpose.name(),
            "domain": self.domain,
            "payload_bytes": self.payload.len(),
            "payload_digest": hex_of(&Sha256::digest(&self.payload)),
        })
    }

    /// 审计里的签名基摘要。签的是 `message`,摘要就只对 `message` 算。
    pub fn message_digest(&self) -> String {
        hex_of(&Sha256::digest(&self.message))
    }

    pub fn sign(&self, key: &LockedSigningKey) -> Result<SignedPurpose> {
        let signature = key.sign(&self.message)?;
        Ok(SignedPurpose {
            signature: hex_of(&signature),
            public_multibase: key.public_multibase().to_owned(),
            purpose: self.tag(),
        })
    }
}

fn application_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let bytes = domain.as_bytes();
    let mut message =
        Vec::with_capacity(APPLICATION_ASSERTION_PREFIX.len() + 2 + bytes.len() + payload.len());
    message.extend_from_slice(APPLICATION_ASSERTION_PREFIX);
    message.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    message.extend_from_slice(bytes);
    message.extend_from_slice(payload);
    message
}

/// 域规则照抄上游 `validate_domain`,一个字都不放宽。
fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty()
        || domain.trim() != domain
        || domain.len() > MAX_DOMAIN_BYTES
        || domain.as_bytes().contains(&0)
    {
        return Err(invalid());
    }
    Ok(())
}

/// 线上 payload 是小写 hex:大写、奇数长度、非 hex 字符一律不收。
fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || text.len() / 2 > MAX_PAYLOAD_BYTES
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok((0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("validated hex"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::record::KeyId;

    fn key() -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [7; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId {
                did: "did:wba:example.com:user:alice".into(),
                kid: "did:wba:example.com:user:alice#device-sign".into(),
                thumbprint: "alice".into(),
            },
            seed,
        )
        .unwrap()
    }

    /// 设备断言签的就是 payload 本身,前面没有任何 daemon 自己加的东西。
    #[test]
    fn device_assertion_signs_the_payload_unchanged() {
        let request = PurposeRequest::from_wire("device_assertion", None, "00ff10").unwrap();
        let signed = request.sign(&key()).unwrap();
        let signature: [u8; 64] = (0..64)
            .map(|i| u8::from_str_radix(&signed.signature[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert!(key().verify(&[0x00, 0xff, 0x10], &signature));
        assert_eq!(signed.signature.len(), 128);
        assert_eq!(signed.purpose, json!({"purpose":"device_assertion"}));
        assert!(signed.public_multibase.starts_with('z'));
    }

    /// 应用断言的前缀和上游逐字节一致:域串 + u16 BE 长度 + 域 + payload。
    #[test]
    fn application_assertion_uses_the_frozen_upstream_prefix() {
        let request =
            PurposeRequest::from_wire("application_assertion", Some("chat.alpha".into()), "616263")
                .unwrap();
        let mut expected = b"anp.identity.application-assertion.v1\0".to_vec();
        expected.extend_from_slice(&10u16.to_be_bytes());
        expected.extend_from_slice(b"chat.alpha");
        expected.extend_from_slice(b"abc");
        assert_eq!(request.message, expected);
        assert_eq!(
            request.tag(),
            json!({"purpose":"application_assertion","domain":"chat.alpha"})
        );
    }

    #[test]
    fn a_domain_belongs_to_exactly_one_purpose() {
        assert!(
            PurposeRequest::new(SigningPurpose::DeviceAssertion, Some("x".into()), b"a").is_err()
        );
        assert!(PurposeRequest::new(SigningPurpose::ApplicationAssertion, None, b"a").is_err());
        for domain in ["", " x", "x ", &"d".repeat(257)] {
            assert!(PurposeRequest::new(
                SigningPurpose::ApplicationAssertion,
                Some(domain.into()),
                b"a"
            )
            .is_err());
        }
        assert!(PurposeRequest::new(
            SigningPurpose::ApplicationAssertion,
            Some("a\0b".into()),
            b"a"
        )
        .is_err());
        let longest = "d".repeat(MAX_DOMAIN_BYTES);
        assert_eq!(
            PurposeRequest::new(
                SigningPurpose::ApplicationAssertion,
                Some(longest.clone()),
                b"a"
            )
            .unwrap()
            .domain(),
            Some(longest.as_str())
        );
    }

    #[test]
    fn payloads_are_bounded_and_hex_is_strict() {
        assert!(PurposeRequest::from_wire("device_assertion", None, "").is_err());
        assert!(PurposeRequest::from_wire("device_assertion", None, "0").is_err());
        assert!(PurposeRequest::from_wire("device_assertion", None, "AB").is_err());
        assert!(PurposeRequest::from_wire("device_assertion", None, "zz").is_err());
        assert!(PurposeRequest::from_wire("device_assertion", None, &"00".repeat(4097)).is_err());
        assert!(PurposeRequest::from_wire("device_assertion", None, &"00".repeat(4096)).is_ok());
        // `authentication` has its own two operations; this surface is not a general signer.
        assert!(PurposeRequest::from_wire("authentication", None, "00").is_err());
        assert!(SigningPurpose::parse("Authentication").is_err());
    }

    #[test]
    fn the_digest_separates_purposes_and_domains() {
        let payload = b"same bytes";
        let device = PurposeRequest::new(SigningPurpose::DeviceAssertion, None, payload).unwrap();
        let alpha = PurposeRequest::new(
            SigningPurpose::ApplicationAssertion,
            Some("chat.alpha".into()),
            payload,
        )
        .unwrap();
        let beta = PurposeRequest::new(
            SigningPurpose::ApplicationAssertion,
            Some("chat.beta".into()),
            payload,
        )
        .unwrap();
        assert_ne!(device.digest(), alpha.digest());
        assert_ne!(alpha.digest(), beta.digest());
        assert_eq!(device.digest(), device.digest());
    }

    /// 审计只留摘要和长度,payload 本身不落盘。
    #[test]
    fn audit_options_carry_no_payload_bytes() {
        let request = PurposeRequest::from_wire("device_assertion", None, "deadbeef").unwrap();
        let options = request.audit_options();
        assert_eq!(options["payload_bytes"], 4);
        assert_eq!(
            options["payload_digest"],
            hex_of(&Sha256::digest([0xde, 0xad, 0xbe, 0xef]))
        );
        assert!(!options.to_string().contains("deadbeef"));
    }
}
