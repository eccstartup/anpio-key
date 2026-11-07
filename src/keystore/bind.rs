//! 把命名钥匙换绑成 DID 绑定的信封（`key bind-did`）。
//!
//! 命名钥匙只有名字、没有 DID；受保护平面登记的是 `{did, kid, thumbprint}`，
//! 而 kid 由一份**已经发布、已经签过**的 DID 文档决定。这里做的不是"换一把
//! 钥匙"，而是把同一把 seed 原样封进一个新信封：DID、公钥、指纹一个字节都
//! 不改，所以已经发布的文档仍然对得上。
//!
//! 三把钥匙的角色来自文档本身：
//! - 根钥匙：`#key-1`，Ed25519，DID 最后一段就是它的指纹；
//! - 设备签名钥匙：`deviceManifest` 的 `signing_key_id`，Ed25519；
//! - 设备协商钥匙：`deviceManifest` 的 `e2ee_key_id`，X25519。
//!
//! 没有 `deviceManifest` 的旧文档退回按关系数组找：`authentication` 里唯一
//! 一把非根的 Ed25519 钥匙，`keyAgreement` 里唯一一把 X25519 钥匙。
//!
//! **源 store 只读。** 输出写到一个全新的空目录，调用方确认迁移成功之后才
//! 决定怎么处理旧的那份副本。

use std::fs;
use std::path::Path;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::Argon2Config;
use crate::error::{KeydError, Result};
use crate::keystore::layout::{self, KeydLayout, SECRET_FILE_MODE};
use crate::keystore::record::{KeyAlgorithm, KeyId, WrappedKey};
use crate::keystore::{device, store, unwrap, wrap};

/// 文档里三种钥匙的角色。角色的名字会写进 `--json` 输出，供接管脚本核对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRole {
    Root,
    DeviceSigning,
    DeviceAgreement,
}

impl IdentityRole {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityRole::Root => "root",
            IdentityRole::DeviceSigning => "device_signing",
            IdentityRole::DeviceAgreement => "device_agreement",
        }
    }
}

/// 一把命名钥匙在文档里的落点。
#[derive(Debug, Clone)]
pub struct IdentityBinding {
    pub role: IdentityRole,
    /// 源 store 里的名字（身份文件 `custody` 里记的那个）。
    pub name: String,
    pub did: String,
    pub kid: String,
    pub thumbprint: String,
    pub algorithm: KeyAlgorithm,
    pub public_multibase: String,
}

/// 身份文件 + 已发布文档推导出的完整换绑计划。
#[derive(Debug, Clone)]
pub struct IdentityPlan {
    pub did: String,
    pub document: Value,
    /// 固定顺序：根、设备签名、设备协商。
    pub bindings: Vec<IdentityBinding>,
}

impl IdentityPlan {
    pub fn binding(&self, role: IdentityRole) -> Option<&IdentityBinding> {
        self.bindings.iter().find(|binding| binding.role == role)
    }
}

/// 读身份文件并推导换绑计划。文件本身不写、不改。
pub fn plan_identity(identity_path: &Path) -> Result<IdentityPlan> {
    let meta = fs::symlink_metadata(identity_path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(KeydError::Permission(format!(
            "{} is not a regular identity file",
            identity_path.display()
        )));
    }
    if meta.len() > 1_048_576 {
        return Err(KeydError::Misuse("identity file is larger than 1 MiB".into()));
    }
    let bytes = fs::read(identity_path)?;
    let identity: Value = serde_json::from_slice(&bytes).map_err(|error| {
        KeydError::Protocol(format!(
            "{} is not a JSON identity: {error}",
            identity_path.display()
        ))
    })?;
    plan_from_identity(&identity)
}

/// 从已经解析好的身份对象推导计划（单测直接走这条）。
pub fn plan_from_identity(identity: &Value) -> Result<IdentityPlan> {
    let did = identity
        .get("did")
        .and_then(Value::as_str)
        .filter(|did| !did.is_empty())
        .ok_or_else(|| KeydError::Did("identity has no `did`".into()))?;
    let document = identity
        .get("did_document")
        .filter(|document| document.is_object())
        .ok_or_else(|| KeydError::Did(format!("identity {did} has no DID document")))?;
    let document_id = document.get("id").and_then(Value::as_str).unwrap_or_default();
    if document_id != did {
        return Err(KeydError::Did(format!(
            "identity says {did}, but its document is {document_id:?}"
        )));
    }
    crate::did::document::verify_path_binding(did, document)?;

    let custody = identity
        .get("custody")
        .filter(|custody| custody.is_object())
        .ok_or_else(|| KeydError::Misuse("identity has no anpio-key custody block".into()))?;
    if custody.get("kind").and_then(Value::as_str) != Some("anpio-key") {
        return Err(KeydError::Misuse(
            "bind-did only adopts identities whose custody kind is `anpio-key`".into(),
        ));
    }
    let root_name = custody_text(custody, "name", "custody.name")?;
    let device_keys = custody
        .get("device_keys")
        .filter(|keys| keys.is_object())
        .ok_or_else(|| KeydError::Misuse("custody has no `device_keys`".into()))?;
    let sign_name = custody_text(device_keys, "sign", "custody.device_keys.sign")?;
    let agreement_name =
        custody_text(device_keys, "agreement", "custody.device_keys.agreement")?;
    if root_name == sign_name || root_name == agreement_name || sign_name == agreement_name {
        return Err(KeydError::Misuse(
            "custody names the same key for two roles".into(),
        ));
    }

    let root_kid = format!("{did}#key-1");
    let root = method_key(document, did, &root_kid, KeyAlgorithm::Ed25519)?;
    if root.thumbprint != crate::crypto::thumbprint::e1_from_did(did)? {
        return Err(KeydError::Did(format!(
            "{did} does not end in the root key's fingerprint {}",
            root.thumbprint
        )));
    }
    require_relationship(document, "assertionMethod", &root_kid)
        .or_else(|_| require_relationship(document, "authentication", &root_kid))
        .map_err(|_| {
            KeydError::Did(format!(
                "the root key {root_kid} is not authorized in the document"
            ))
        })?;

    let (sign_kid, agreement_kid) = device_kids(document, did, &root_kid)?;
    let sign = method_key(document, did, &sign_kid, KeyAlgorithm::Ed25519)?;
    require_relationship(document, "authentication", &sign_kid)?;
    let agreement = method_key(document, did, &agreement_kid, KeyAlgorithm::X25519)?;
    require_relationship(document, "keyAgreement", &agreement_kid)?;

    let bindings = vec![
        binding(IdentityRole::Root, root_name, did, root_kid, root),
        binding(IdentityRole::DeviceSigning, sign_name, did, sign_kid, sign),
        binding(
            IdentityRole::DeviceAgreement,
            agreement_name,
            did,
            agreement_kid,
            agreement,
        ),
    ];
    Ok(IdentityPlan {
        did: did.to_string(),
        document: document.clone(),
        bindings,
    })
}

/// 同一把 seed 换一个 `KeyId` 重新封装。
///
/// 公钥、算法、标签都来自**已经解开并自检过的**源信封；调用方不能替换其中
/// 任何一项。硬件绑定的信封在这里拒绝：AAD 里绑着那台机器的熵，换 id 就要
/// 换 AAD，换 AAD 就解不开了。
pub fn reseal(
    wrapped: &WrappedKey,
    binding: &IdentityBinding,
    passphrase: &[u8],
    device_secret: &LockedBytes,
) -> Result<WrappedKey> {
    if !wrapped.is_named() {
        return Err(KeydError::Misuse(format!(
            "{} is already DID-bound; bind-did only adopts named keys",
            wrapped.id.thumbprint
        )));
    }
    if wrapped.hardware.is_some() || wrapped.hs_ciphertext.is_some() {
        return Err(KeydError::Misuse(format!(
            "key {} is bound to a hardware root and cannot be re-addressed",
            binding.name
        )));
    }
    if wrapped.algorithm != binding.algorithm {
        return Err(KeydError::Misuse(format!(
            "key {} is {:?}, but the document names an {:?} method for {}",
            binding.name,
            wrapped.algorithm,
            binding.algorithm,
            binding.role.as_str()
        )));
    }
    if wrapped.id.thumbprint != binding.thumbprint {
        return Err(KeydError::Misuse(format!(
            "key {} has fingerprint {}, but the document's agentMethod needs {}",
            binding.name, wrapped.id.thumbprint, binding.thumbprint
        )));
    }
    if wrapped.public_multibase != binding.public_multibase {
        return Err(KeydError::Misuse(format!(
            "key {} advertises a public key that is not the one in the document",
            binding.name
        )));
    }

    let seed = unwrap::seed_of(wrapped, passphrase, device_secret)?;
    let sealed = wrap::seal(wrap::SealRequest {
        id: KeyId {
            did: binding.did.clone(),
            kid: binding.kid.clone(),
            thumbprint: binding.thumbprint.clone(),
        },
        algorithm: wrapped.algorithm,
        public_multibase: wrapped.public_multibase.clone(),
        label: wrapped.label.clone(),
        name: String::new(),
        passphrase,
        device_secret,
        seed: &seed,
        argon: Argon2Config {
            m_cost: wrapped.kdf.m_cost,
            t_cost: wrapped.kdf.t_cost,
            p_cost: wrapped.kdf.p_cost,
        },
        hardware: None,
    })?;
    Ok(sealed)
}

/// 把命名 store 换绑进一个全新的空目录。
///
/// 每把钥匙单独读一次口令；口令只经 `passphrase_for` 回调，不落任何文件。
/// 返回按根、设备签名、设备协商顺序封好的信封。
pub fn bind_store(
    source: &KeydLayout,
    out: &KeydLayout,
    identity_path: &Path,
    mut passphrase_for: impl FnMut(&IdentityBinding) -> Result<Zeroizing<String>>,
) -> Result<Vec<WrappedKey>> {
    require_real_source(source)?;
    require_empty_output(source, out)?;
    let plan = plan_identity(identity_path)?;
    let device_secret = device::load(source)?;

    out.ensure()?;
    let mut sealed = Vec::with_capacity(plan.bindings.len());
    for binding in &plan.bindings {
        let wrapped = store::load_named(source, &binding.name)?;
        let passphrase = passphrase_for(binding)?;
        let bound = reseal(&wrapped, binding, passphrase.as_bytes(), &device_secret)?;
        store::save_new(out, &bound)?;
        sealed.push(bound);
    }

    // `device.secret` 是两把钥匙共用的那 32 字节。它必须原样过去：重新生成
    // 一个会让解不开任何一把已经封好的信封。
    let mut secret = layout::read_secret_file(&source.device_secret_path())?;
    let result = layout::write_atomic(
        &out.device_secret_path(),
        &secret,
        SECRET_FILE_MODE,
    );
    zeroize::Zeroize::zeroize(&mut secret);
    result?;

    // 文档原样复制，不重签：签名覆盖的字节没有变，重签只会多出一份不同的
    // proof 让人去分辨。
    store::write_did_document(out, &plan.did, &plan.document)?;
    Ok(sealed)
}

fn require_real_source(source: &KeydLayout) -> Result<()> {
    let meta = fs::symlink_metadata(source.root())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(KeydError::Permission(format!(
            "source root {} is not a real directory",
            source.root().display()
        )));
    }
    Ok(())
}

fn require_empty_output(source: &KeydLayout, out: &KeydLayout) -> Result<()> {
    if out.root() == source.root()
        || out.root().starts_with(source.root())
        || source.root().starts_with(out.root())
    {
        return Err(KeydError::Misuse(
            "the output directory must not be the source store or inside it".into(),
        ));
    }
    match fs::symlink_metadata(out.root()) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(KeydError::Permission(format!(
                    "output {} is not a real directory",
                    out.root().display()
                )));
            }
            if fs::read_dir(out.root())?.next().is_some() {
                return Err(KeydError::Misuse(format!(
                    "output {} must be empty; refusing to mix two key stores",
                    out.root().display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(KeydError::Io(error)),
    }
    Ok(())
}

#[derive(Debug)]
struct MethodKey {
    thumbprint: String,
    public_multibase: String,
}

fn binding(
    role: IdentityRole,
    name: String,
    did: &str,
    kid: String,
    key: MethodKey,
) -> IdentityBinding {
    IdentityBinding {
        role,
        name,
        did: did.to_string(),
        kid,
        thumbprint: key.thumbprint,
        algorithm: match role {
            IdentityRole::DeviceAgreement => KeyAlgorithm::X25519,
            _ => KeyAlgorithm::Ed25519,
        },
        public_multibase: key.public_multibase,
    }
}

fn custody_text(custody: &Value, field: &str, label: &str) -> Result<String> {
    custody
        .get(field)
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| KeydError::Misuse(format!("{label} is missing or empty")))
}

/// 找到方法、核对控制器和曲线，并把文档上写的公钥、指纹一起算出来。
fn method_key(
    document: &Value,
    did: &str,
    kid: &str,
    expected: KeyAlgorithm,
) -> Result<MethodKey> {
    let method = anp::authentication::find_verification_method(document, kid).ok_or_else(|| {
        KeydError::Did(format!("the document has no verification method {kid}"))
    })?;
    let controller = method.get("controller").and_then(Value::as_str);
    if controller != Some(did) {
        return Err(KeydError::Did(format!(
            "{kid} is controlled by {controller:?}, not {did}"
        )));
    }
    let material = anp::authentication::extract_public_key(&method)
        .map_err(|_| KeydError::Did(format!("{kid} carries an unreadable public key")))?;
    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KeydError::Did(format!(
                "{kid} has no publicKeyMultibase; bind-did needs the published multikey"
            ))
        })?;

    let (thumbprint, parsed_matches) = match (&material, expected) {
        (anp::PublicKeyMaterial::Ed25519(public), KeyAlgorithm::Ed25519) => {
            let matches =
                crate::crypto::thumbprint::ed25519_from_multibase(multibase).is_ok_and(|parsed| {
                    parsed == *public
                });
            (crate::crypto::thumbprint::e1_segment(public)?, matches)
        }
        (anp::PublicKeyMaterial::X25519(bytes), KeyAlgorithm::X25519) => {
            let matches =
                crate::crypto::thumbprint::x25519_from_multibase(multibase).is_ok_and(|parsed| {
                    parsed == *bytes
                });
            let public = x25519_dalek::PublicKey::from(*bytes);
            (crate::crypto::thumbprint::x1_segment(&public), matches)
        }
        (_, expected) => {
            return Err(KeydError::Did(format!(
                "{kid} is not a {expected:?} key"
            )))
        }
    };
    if !parsed_matches {
        return Err(KeydError::Did(format!(
            "{kid} advertises a multibase that is not its own public key"
        )));
    }
    Ok(MethodKey {
        thumbprint,
        public_multibase: multibase.to_string(),
    })
}

fn require_relationship(document: &Value, relationship: &str, kid: &str) -> Result<()> {
    if authorized(document, relationship, kid) {
        return Ok(());
    }
    Err(KeydError::Did(format!(
        "{kid} is not authorized in `{relationship}`"
    )))
}

fn authorized(document: &Value, relationship: &str, kid: &str) -> bool {
    document
        .get(relationship)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str().or_else(|| item.get("id").and_then(Value::as_str)) == Some(kid)
            })
        })
}

/// 设备签名 / 协商 kid。优先读 `deviceManifest`，这是 awiki 要求的单一设备
/// 文档里权威的绑定；没有清单时退回按关系数组找唯一候选。
fn device_kids(document: &Value, did: &str, root_kid: &str) -> Result<(String, String)> {
    if let Some(manifest) = document.get("deviceManifest") {
        let devices = manifest
            .get("devices")
            .and_then(Value::as_array)
            .ok_or_else(|| KeydError::Did("deviceManifest has no `devices` array".into()))?;
        if devices.len() != 1 {
            return Err(KeydError::Did(format!(
                "custody names one device, but the document's manifest lists {}",
                devices.len()
            )));
        }
        let device = &devices[0];
        let sign = device
            .get("signing_key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| KeydError::Did("deviceManifest has no signing_key_id".into()))?;
        let agreement = device
            .get("e2ee_key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| KeydError::Did("deviceManifest has no e2ee_key_id".into()))?;
        return Ok((sign.to_string(), agreement.to_string()));
    }

    let sign = sole_relationship_key(
        document,
        did,
        &["authentication"],
        root_kid,
        KeyAlgorithm::Ed25519,
        "-sign",
    )?;
    let agreement = sole_relationship_key(
        document,
        did,
        &["keyAgreement"],
        root_kid,
        KeyAlgorithm::X25519,
        "-agreement",
    )?;
    Ok((sign, agreement))
}

fn sole_relationship_key(
    document: &Value,
    did: &str,
    relationships: &[&str],
    root_kid: &str,
    expected: KeyAlgorithm,
    suffix: &str,
) -> Result<String> {
    let mut candidates = Vec::new();
    for relationship in relationships {
        let Some(items) = document.get(*relationship).and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            let Some(kid) = item
                .as_str()
                .or_else(|| item.get("id").and_then(Value::as_str))
            else {
                continue;
            };
            if kid == root_kid || candidates.iter().any(|seen| seen == kid) {
                continue;
            }
            let Some(method) = anp::authentication::find_verification_method(document, kid) else {
                continue;
            };
            let Ok(material) = anp::authentication::extract_public_key(&method) else {
                continue;
            };
            let matches = matches!(
                (&material, expected),
                (anp::PublicKeyMaterial::Ed25519(_), KeyAlgorithm::Ed25519)
                    | (anp::PublicKeyMaterial::X25519(_), KeyAlgorithm::X25519)
            );
            if matches
                && kid.starts_with(did)
                && kid.rsplit_once('#').is_some_and(|(_, fragment)| {
                    fragment.ends_with(suffix) && !fragment.is_empty()
                })
            {
                candidates.push(kid.to_string());
            }
        }
    }
    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 => Err(KeydError::Did(format!(
            "the document has no unique {expected:?} `*{suffix}` key in {}",
            relationships.join("/")
        ))),
        _ => Err(KeydError::Did(format!(
            "the document has {} `*{suffix}` keys; refusing to guess which device this identity is",
            candidates.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public, seed_to_x25519_public, SealRequest};
    use crate::sign::key::x25519_public_from_seed;
    use crate::sign::Signer;
    use serde_json::json;

    const PASS: &[u8] = b"correct horse battery staple";

    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn device(byte: u8) -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [byte; 32]).unwrap()
    }

    fn seed(byte: u8) -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [byte; 32]).unwrap()
    }

    struct Fixture {
        root: KeydLayout,
        identity_path: std::path::PathBuf,
        did: String,
        sign_kid: String,
        agreement_kid: String,
        sign_seed: LockedBytes,
    }

    fn fixture(tag: &str) -> Fixture {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "keyd-bind-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let root = KeydLayout::at(dir.join("source"));
        root.ensure().unwrap();
        fs::write(root.device_secret_path(), [7u8; 32]).unwrap();
        fs::set_permissions(
            root.device_secret_path(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let root_seed = seed(1);
        let sign_seed = seed(2);
        let agreement_seed = seed(3);
        let (root_public, root_mb) = seed_to_public(&root_seed);
        let (sign_public, sign_mb) = seed_to_public(&sign_seed);
        let (agreement_public, agreement_mb) = seed_to_x25519_public(&agreement_seed);

        let root_thumb = crate::crypto::thumbprint::e1_segment(&root_public).unwrap();
        let sign_thumb = crate::crypto::thumbprint::e1_segment(&sign_public).unwrap();
        let agreement_thumb = crate::crypto::thumbprint::x1_segment(
            &x25519_dalek::PublicKey::from(agreement_public),
        );

        // 文档必须真的签过：`plan_identity` 和迁移一样会跑上游的规范性检查，
        // 一份手写的假 proof 在第一步就会被拒。这里用真实的上游构造器 + 根钥匙
        // 签名，顺带把 deviceManifest 放进签名基。
        use anp::authentication::DidVerificationRelationship as Relationship;
        let spec = crate::did::document::DidDocumentSpec::new(
            "example.com",
            vec!["user".into(), "alice".into()],
        );
        let (did, mut unsigned) = crate::did::document::build_unsigned_with(
            &spec,
            &root_public,
            vec![
                crate::did::document::ExtraKey::new(
                    "alice-default-sign",
                    sign_public,
                    vec![Relationship::Authentication, Relationship::AssertionMethod],
                ),
                crate::did::document::ExtraKey::agreement(
                    "alice-default-agreement",
                    agreement_public,
                    vec![Relationship::KeyAgreement],
                ),
            ],
        )
        .unwrap();
        let root_kid = format!("{did}#key-1");
        let sign_kid = format!("{did}#alice-default-sign");
        let agreement_kid = format!("{did}#alice-default-agreement");
        unsigned["deviceManifest"] = json!({
            "type": "ANPDeviceManifest",
            "devices": [{
                "device_id": "alice/default",
                "signing_key_id": sign_kid,
                "e2ee_key_id": agreement_kid,
            }],
        });
        let signing_key = crate::sign::LockedSigningKey::from_seed(
            KeyId {
                did: String::new(),
                kid: String::new(),
                thumbprint: String::new(),
            },
            seed(1),
        )
        .unwrap();
        let document =
            crate::did::document::sign_document(&unsigned, &signing_key, &root_kid).unwrap();

        for (name, algorithm, thumb, mb, key_seed) in [
            (
                "named-root",
                KeyAlgorithm::Ed25519,
                root_thumb.clone(),
                root_mb.clone(),
                &root_seed,
            ),
            (
                "named-sign",
                KeyAlgorithm::Ed25519,
                sign_thumb.clone(),
                sign_mb.clone(),
                &sign_seed,
            ),
            (
                "named-agree",
                KeyAlgorithm::X25519,
                agreement_thumb.clone(),
                agreement_mb.clone(),
                &agreement_seed,
            ),
        ] {
            let wrapped = seal(SealRequest {
                id: KeyId {
                    did: String::new(),
                    kid: String::new(),
                    thumbprint: thumb,
                },
                algorithm,
                public_multibase: mb,
                label: "named".into(),
                name: name.into(),
                passphrase: PASS,
                device_secret: &device(7),
                seed: key_seed,
                argon: fast(),
                hardware: None,
            })
            .unwrap();
            crate::keystore::store::save_named(&root, &wrapped).unwrap();
        }

        let identity = json!({
            "did": did,
            "did_document": document,
            "custody": {
                "kind": "anpio-key",
                "name": "named-root",
                "device_keys": {"sign": "named-sign", "agreement": "named-agree"},
            },
        });
        let identity_path = dir.join("identity.json");
        fs::write(&identity_path, serde_json::to_vec_pretty(&identity).unwrap()).unwrap();

        Fixture {
            root,
            identity_path,
            did,
            sign_kid,
            agreement_kid,
            sign_seed,
        }
    }

    #[test]
    fn plan_uses_the_document_for_every_kid() {
        let fixture = fixture("plan");
        let plan = plan_identity(&fixture.identity_path).unwrap();
        assert_eq!(plan.did, fixture.did);
        assert_eq!(plan.bindings.len(), 3);
        assert_eq!(plan.binding(IdentityRole::Root).unwrap().kid, format!("{}#key-1", fixture.did));
        assert_eq!(
            plan.binding(IdentityRole::DeviceSigning).unwrap().kid,
            fixture.sign_kid
        );
        assert_eq!(
            plan.binding(IdentityRole::DeviceAgreement).unwrap().kid,
            fixture.agreement_kid
        );
        assert_eq!(
            plan.binding(IdentityRole::DeviceAgreement).unwrap().algorithm,
            KeyAlgorithm::X25519
        );
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn reseal_keeps_the_seed_public_key_and_thumbprint() {
        let fixture = fixture("reseal");
        let plan = plan_identity(&fixture.identity_path).unwrap();
        let device_secret = device(7);
        let mut seeds = Vec::new();
        for binding in &plan.bindings {
            let wrapped = crate::keystore::store::load_named(&fixture.root, &binding.name).unwrap();
            let bound = reseal(&wrapped, binding, PASS, &device_secret).unwrap();
            assert!(!bound.is_named());
            assert_eq!(bound.id.did, fixture.did);
            assert_eq!(bound.id.kid, binding.kid);
            assert_eq!(bound.id.thumbprint, binding.thumbprint);
            assert_eq!(bound.public_multibase, binding.public_multibase);
            assert_eq!(bound.algorithm, binding.algorithm);
            match binding.algorithm {
                KeyAlgorithm::Ed25519 => {
                    let key = unwrap::unlock(&bound, PASS, &device_secret).unwrap();
                    assert_eq!(key.public_multibase(), binding.public_multibase);
                }
                KeyAlgorithm::X25519 => {
                    let derived = unwrap::seed_of(&bound, PASS, &device_secret).unwrap();
                    let public = x25519_public_from_seed(&derived);
                    assert_eq!(
                        crate::crypto::thumbprint::x25519_multibase(&public),
                        binding.public_multibase
                    );
                }
                _ => unreachable!(),
            }
            seeds.push(bound);
        }
        assert_eq!(seeds.len(), 3);
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn bind_store_writes_a_complete_second_store_and_leaves_the_source_alone() {
        let fixture = fixture("store");
        let out = KeydLayout::at(fixture.root.root().parent().unwrap().join("staging"));
        let before: Vec<_> = fixture
            .root
            .list_key_paths()
            .unwrap()
            .iter()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();

        let bound = bind_store(&fixture.root, &out, &fixture.identity_path, |binding| {
            assert!(binding.kid.contains(&fixture.did));
            Ok(Zeroizing::new(String::from_utf8(PASS.to_vec()).unwrap()))
        })
        .unwrap();
        assert_eq!(bound.len(), 3);

        // 输出能通过迁移前的那套检查。
        let inspection = crate::security::migration::inspect(out.root(), false).unwrap();
        assert_eq!(inspection["keys"].as_array().unwrap().len(), 3);
        assert!(out.device_secret_path().exists());
        assert!(out.did_path(&fixture.did).exists());

        let after: Vec<_> = fixture
            .root
            .list_key_paths()
            .unwrap()
            .iter()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();
        assert_eq!(before, after, "bind-did must not touch the source store");

        // seed 没变：用源信封和输出信封各解一次，公钥必须一致。
        let sign_thumb =
            crate::crypto::thumbprint::e1_segment(&seed_to_public(&fixture.sign_seed).0).unwrap();
        assert_eq!(
            crate::keystore::store::load_named(&fixture.root, "named-sign")
                .unwrap()
                .public_multibase,
            crate::keystore::store::load(&out, &sign_thumb)
                .unwrap()
                .public_multibase
        );
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn a_non_empty_output_is_refused() {
        let fixture = fixture("nonempty");
        let out = KeydLayout::at(fixture.root.root().parent().unwrap().join("staging"));
        out.ensure().unwrap();
        fs::write(out.root().join("keep"), b"x").unwrap();
        let error = bind_store(&fixture.root, &out, &fixture.identity_path, |_| {
            Ok(Zeroizing::new(String::from_utf8(PASS.to_vec()).unwrap()))
        })
        .unwrap_err();
        assert!(error.to_string().contains("must be empty"), "{error}");
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn a_manifest_with_more_than_one_device_is_refused() {
        let document = json!({
            "deviceManifest": {
                "type": "ANPDeviceManifest",
                "devices": [{"device_id": "a"}, {"device_id": "b"}],
            },
        });
        let error = device_kids(&document, "did:wba:example.com:user:alice:e1_x", "did:wba:example.com:user:alice:e1_x#key-1")
            .unwrap_err();
        assert!(error.to_string().contains("lists 2"), "{error}");
    }

    #[test]
    fn a_document_that_is_not_the_identitys_own_is_refused() {
        let fixture = fixture("other-doc");
        let mut identity: Value =
            serde_json::from_slice(&fs::read(&fixture.identity_path).unwrap()).unwrap();
        identity["did_document"]["id"] = json!("did:wba:example.com:user:mallory:e1_x");
        let error = plan_from_identity(&identity).unwrap_err();
        assert!(error.to_string().contains("its document is"), "{error}");
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn a_wrong_curve_for_the_agreement_role_is_refused() {
        let fixture = fixture("curve");
        let plan = plan_identity(&fixture.identity_path).unwrap();
        let wrapped =
            crate::keystore::store::load_named(&fixture.root, "named-sign").unwrap();
        let mut binding = plan.binding(IdentityRole::DeviceAgreement).unwrap().clone();
        binding.name = "named-sign".into();
        binding.kid = fixture.sign_kid.clone();
        binding.thumbprint = wrapped.id.thumbprint.clone();
        binding.public_multibase = wrapped.public_multibase.clone();
        let error = reseal(&wrapped, &binding, PASS, &device(7)).unwrap_err();
        assert!(error.to_string().contains("is Ed25519, but"), "{error}");
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }

    #[test]
    fn a_hardware_bound_envelope_cannot_be_re_addressed() {
        let fixture = fixture("hardware");
        let plan = plan_identity(&fixture.identity_path).unwrap();
        let binding = plan.binding(IdentityRole::DeviceSigning).unwrap();
        let wrapped =
            crate::keystore::store::load_named(&fixture.root, "named-sign").unwrap();
        let mut wrapped = wrapped;
        wrapped.hardware = Some(crate::keystore::record::HardwareRoot::SecureEnclave {
            tag: "anp-keyd/test".into(),
        });
        wrapped.hs_ciphertext = Some(String::new());
        let error = reseal(&wrapped, binding, PASS, &device(7)).unwrap_err();
        assert!(error.to_string().contains("hardware root"), "{error}");
        let _ = fs::remove_dir_all(fixture.root.root().parent().unwrap());
    }
}
