//! 生成一把新的 did:wba 密钥,并把它的信封写下去。
//!
//! 这里的顺序是有讲究的:**先有 seed,再由 seed 推出公钥,再由公钥和坐标
//! 算出 DID**。反过来(先定 DID 再想办法凑公钥)是不可能做到的 —— 也就
//! 意味着 DID 的 `e1_` 段天然就是公钥的指纹,不需要额外信任任何东西。
//!
//! **这里不构造文档。** 一份文档是"协议面"的东西(service 条目、agent
//! description……),`keygen` 一个字节都用不上 —— 它只要 DID 字符串。
//! 文档由 [`crate::did::document`] 从规格构造、由 `publish` 签名,规格本身
//! 是外部的(见 [`crate::did::spec`])。

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::Argon2Config;
use crate::crypto::thumbprint::e1_segment;
use crate::did::document::{DidDocumentSpec, ExtraKey};
use crate::did::spec::compose_did_wba;
use crate::error::Result;
use crate::keystore::hardware::{self, HardwareChoice};
use crate::keystore::layout::KeydLayout;
use crate::keystore::record::{KeyAlgorithm, KeyId, WrappedKey};
use crate::keystore::{device, store, wrap};

/// 一次生成的产物。
pub struct Created {
    /// 要落盘的那个信封。
    pub wrapped: WrappedKey,
    pub did: String,
    /// 根密钥验证方法的完整 id(`did#key-1`)。
    pub verification_method: String,
}

/// 只生成,不碰磁盘。
///
/// `hardware` 在这里才用得上,而不是由调用方先跑:硬件根的定位符**就是这把
/// 钥匙的指纹**,而指纹要等 seed 和公钥都算出来才有。所以顺序只能是
/// seed → 指纹 → 封硬件 → 封信封。
///
/// 硬件那一趟失败会**整个连带失败**,不会留下"信封写了一半"的状态:信封由
/// 调用方在本函数返回之后才落盘。
pub fn generate(
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<Created> {
    // seed 从生到封一直待在锁定区里,中途不出现裸副本。
    let seed = LockedBytes::generate()?;
    let (verifying, public_multibase) = wrap::seed_to_public(&seed);
    let thumbprint = e1_segment(&verifying)?;

    // DID 由坐标 + 公钥合成 —— `e1_` 段就是我们刚算出的那个指纹,所以
    // 「DID 里的公钥」和「信封里的公钥」必然自洽,不需要事后核对。
    let did = compose_did_wba(spec, &verifying)?;
    let verification_method = format!("{did}#{}", spec.fragment);

    // 要硬件绑定而没有硬件根 → 这里是**拒绝**发生的地方,不是降级发生的地方。
    let hardware = hardware::seal_new(hardware, &thumbprint)?;

    let wrapped = wrap::seal(wrap::SealRequest {
        id: KeyId {
            did: did.clone(),
            kid: verification_method.clone(),
            thumbprint,
        },
        algorithm: KeyAlgorithm::Ed25519,
        public_multibase,
        label: label.to_string(),
        passphrase,
        device_secret,
        seed: &seed,
        argon,
        hardware,
    })?;

    Ok(Created { wrapped, did, verification_method })
}

/// 生成并落盘:信封进 `keys/`,设备密钥不在就顺手建一把。
///
/// DID 文档**不**在这里写 —— 没有签名的文档写到磁盘上只会让人误以为
/// 它已经发布了。`publish` 负责签完再写。
pub fn create(
    layout: &KeydLayout,
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<Created> {
    layout.ensure()?;
    let device_secret = device::load_or_create(layout)?;

    let created = generate(spec, label, passphrase, &device_secret, argon, hardware)?;
    store::save_new(layout, &created.wrapped)?;
    Ok(created)
}

/// 给一个**已经存在**的 DID 造一把新钥匙 —— 热密钥或者恢复密钥。
///
/// 和 [`generate`] 只差一处,但那一处是本质的:`generate` 让上游按新公钥算
/// 出**一个新 DID**(绑定密钥的指纹就是 DID 的最后一段);这里公钥要挂到
/// **既有的** DID 上,所以那把钥匙的指纹和 DID 的最后一段**必然不同**,
/// 它的信封文件名是它自己的指纹算出来的。
///
/// 这条差别往下渗透到好几处,最要命的一处是:`keys/<DID 的 e1_ 段>.json`
/// 这个找钥匙的规则对热密钥**不成立**(见
/// [`crate::keystore::store::envelopes_for_did`])。所以这里把 `did` 交给
/// 调用方拿着的那个,而不是从公钥反推一个 —— 反推出来的会是另一个 DID。
///
/// `relationships` 由调用方给:热密钥是 `authentication`,恢复密钥是
/// `assertionMethod`。上游把"关系"和"角色"做成了一对一,所以这个选择决定
/// 了这把钥匙在文档里能干什么,不能事后补。
// 八个参数,每一个都是这条路上必须有人说的一个决定,而且调用点大多在 CLI 的
// 解析层 —— 打成一个 `struct` 只会把同一批字段搬个地方,再多一层解构。这
// 个 allow 和 `tss-esapi` 在同样的函数上打的是同一个(`create`/`create_primary`
// 也都是七八个 `Option` 参数)。
#[allow(clippy::too_many_arguments)]
pub fn generate_extra(
    did: &str,
    fragment: &str,
    relationships: Vec<anp::authentication::DidVerificationRelationship>,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<(WrappedKey, ExtraKey)> {
    let seed = LockedBytes::generate()?;
    let (verifying, public_multibase) = wrap::seed_to_public(&seed);
    // 指纹算的是**这把**钥匙,不是 DID 最后一段。
    let thumbprint = e1_segment(&verifying)?;

    let hardware = hardware::seal_new(hardware, &thumbprint)?;

    let wrapped = wrap::seal(wrap::SealRequest {
        id: KeyId {
            did: did.to_string(),
            kid: format!("{did}#{fragment}"),
            thumbprint,
        },
        algorithm: KeyAlgorithm::Ed25519,
        public_multibase,
        label: label.to_string(),
        passphrase,
        device_secret,
        seed: &seed,
        argon,
        hardware,
    })?;

    Ok((wrapped, ExtraKey::new(fragment, verifying, relationships)))
}

/// [`generate_extra`] 再落盘。钥匙先写、文档后写 —— 反过来的话,一份
/// 指向"本机没有的钥匙"的文档会先落地,而那是一份**谁也签不出来的**文档。
#[allow(clippy::too_many_arguments)] // 见 `generate_extra` 上面那一段
pub fn create_extra(
    layout: &KeydLayout,
    did: &str,
    fragment: &str,
    relationships: Vec<anp::authentication::DidVerificationRelationship>,
    label: &str,
    passphrase: &[u8],
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<(WrappedKey, ExtraKey)> {
    layout.ensure()?;
    let device_secret = device::load_or_create(layout)?;

    let (wrapped, key) = generate_extra(
        did,
        fragment,
        relationships,
        label,
        passphrase,
        &device_secret,
        argon,
        hardware,
    )?;
    // `save_new`:同一个指纹再生成一次是不可能的(除非运气好到撞上 2^-256),
    // 但万一撞上,盖掉的是**这个文件里唯一一份** seed。
    store::save_new(layout, &wrapped)?;
    Ok((wrapped, key))
}

/// 给一个既有 DID 造一把**协商键**(`{device}-agreement`)。
///
/// 和 [`generate_extra`] 只差曲线:seed 还是那 32 字节,信封的
/// `algorithm` 写 `0x03`,指纹走 `x1_`(X25519 的 JWK 指纹)。文档那边的
/// 角色由 [`ExtraKey::agreement`] 定死成 `keyAgreement` —— 上游只认这一种
/// 组合,而 X25519 也确实不能签名。
#[allow(clippy::too_many_arguments)] // 与 `generate_extra` 同一批决定
pub fn generate_agreement(
    did: &str,
    fragment: &str,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<(WrappedKey, ExtraKey)> {
    let seed = LockedBytes::generate()?;
    let (public, public_multibase) = wrap::seed_to_x25519_public(&seed);
    let thumbprint = crate::crypto::thumbprint::x1_segment(&x25519_dalek::PublicKey::from(public));

    let hardware = hardware::seal_new(hardware, &thumbprint)?;

    let wrapped = wrap::seal(wrap::SealRequest {
        id: KeyId {
            did: did.to_string(),
            kid: format!("{did}#{fragment}"),
            thumbprint,
        },
        algorithm: KeyAlgorithm::X25519,
        public_multibase,
        label: label.to_string(),
        passphrase,
        device_secret,
        seed: &seed,
        argon,
        hardware,
    })?;

    Ok((
        wrapped,
        ExtraKey::agreement(
            fragment,
            public,
            vec![anp::authentication::DidVerificationRelationship::KeyAgreement],
        ),
    ))
}

/// [`generate_agreement`] 再落盘。
#[allow(clippy::too_many_arguments)] // 见 `generate_extra` 上面那一段
pub fn create_agreement(
    layout: &KeydLayout,
    did: &str,
    fragment: &str,
    label: &str,
    passphrase: &[u8],
    argon: Argon2Config,
    hardware: HardwareChoice,
) -> Result<(WrappedKey, ExtraKey)> {
    layout.ensure()?;
    let device_secret = device::load_or_create(layout)?;
    let (wrapped, key) = generate_agreement(
        did,
        fragment,
        label,
        passphrase,
        &device_secret,
        argon,
        hardware,
    )?;
    store::save_new(layout, &wrapped)?;
    Ok((wrapped, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::thumbprint::e1_from_did;
    use crate::did::document::{build_unsigned, ROOT_FRAGMENT};
    use crate::sign::Signer;
    use serde_json::Value;

    fn fast() -> Argon2Config {
        Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    fn device() -> LockedBytes {
        LockedBytes::fill(|d| *d = [0x33; 32]).unwrap()
    }

    #[test]
    fn the_did_binds_the_envelope_public_key() {
        let c = generate(&spec(), "alice", b"pw", &device(), fast(), HardwareChoice::None).unwrap();
        let root = c.wrapped.verifying_key().unwrap();

        // DID 最后一段 == e1_ 段 == KeyId.thumbprint
        assert_eq!(e1_from_did(&c.did).unwrap(), c.wrapped.id.thumbprint);
        assert!(c.did.ends_with(&c.wrapped.id.thumbprint));
        assert_eq!(c.wrapped.id.did, c.did);
        assert_eq!(
            c.wrapped.id.kid,
            format!("{}#{}", c.did, ROOT_FRAGMENT),
            "the kid must be a real verification method id in the document"
        );

        // 合成的 DID 就是文档构建器会写进 `id` 的那一个 —— 这里没有第二条
        // 拼 DID 的路,`keygen` 拿到的是同一份文档会用的那个字符串。
        let (from_document, document) = build_unsigned(&spec(), &root).unwrap();
        assert_eq!(compose_did_wba(&spec(), &root).unwrap(), c.did);
        assert_eq!(from_document, c.did);
        assert_eq!(document["id"], Value::String(c.did.clone()));

        // 信封上写的公钥就是文档里写的公钥。
        let methods = document["verificationMethod"].as_array().unwrap();
        assert!(methods
            .iter()
            .any(|m| m["publicKeyMultibase"] == Value::String(c.wrapped.public_multibase.clone())));
    }

    #[test]
    fn two_generated_keys_never_collide() {
        let a = generate(&spec(), "alice", b"pw", &device(), fast(), HardwareChoice::None).unwrap();
        let b = generate(&spec(), "alice", b"pw", &device(), fast(), HardwareChoice::None).unwrap();
        assert_ne!(a.did, b.did, "each key must get its own DID");
        assert_ne!(a.wrapped.sk_ciphertext, b.wrapped.sk_ciphertext);
    }

    #[test]
    fn create_writes_an_envelope_that_loads_back() {
        let dir = std::env::temp_dir().join(format!("keyd-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir.clone());
        let created = create(&layout, &spec(), "alice", b"pw", fast(), HardwareChoice::None).unwrap();

        // 信封在,设备密钥也在(create 顺手建的)。
        let loaded = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
        assert_eq!(loaded.id.did, created.did);
        assert!(device::exists(&layout));

        // 但没有签名的文档不该出现在 dids/ 里。
        assert!(
            !layout.did_path(&created.did).exists(),
            "create must not publish an unsigned document"
        );

        // 用刚建出来的 device.secret 能解开它。
        let device_secret = device::load(&layout).unwrap();
        let key = crate::keystore::unlock(&loaded, b"pw", &device_secret).unwrap();
        assert_eq!(key.public_multibase(), created.wrapped.public_multibase);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
