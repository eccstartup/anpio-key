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

/// 一个助记词铸出来的整套身份:四把钥匙、同一份文档。
///
/// 四把的 seed **全部由同一个根 seed 推出**(`key-1` 是它本身,另外三把各走
/// 一条 HKDF 域串,见 [`crate::crypto::derive`])。所以纸丢了就是全套丢了,
/// 纸还在就是全套都在 —— 这是助记词能称作"备份"的唯一理由。
///
/// `extras` 和 `document_keys` 一一对应且同序:前者是落盘的信封,后者是要
/// 挂进 DID 文档的验证方法。
pub struct Identity {
    pub did: String,
    pub root: WrappedKey,
    pub extras: Vec<WrappedKey>,
    pub document_keys: Vec<ExtraKey>,
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
    generate_from_seed(spec, label, passphrase, device_secret, argon, hardware, &seed)
}

/// 同上,但 seed 由调用方给 —— 助记词恢复和"一个助记词四把钥匙"走这条。
///
/// 和 [`generate`] 只差 seed 从哪来,其余每一步必须**逐字相同**:两种来源
/// 落下的信封只有 seed 不同,封装参数、AAD、硬件绑定全是一套代码。
pub fn generate_from_seed(
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
    seed: &LockedBytes,
) -> Result<Created> {
    let (verifying, public_multibase) = wrap::seed_to_public(seed);

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
        seed,
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
    generate_extra_from_seed(
        did,
        fragment,
        relationships,
        label,
        passphrase,
        device_secret,
        argon,
        hardware,
        &seed,
    )
}

/// 同上,但 seed 由调用方给 —— 助记词恢复时热密钥和设备签名密钥走这条。
#[allow(clippy::too_many_arguments)]
pub fn generate_extra_from_seed(
    did: &str,
    fragment: &str,
    relationships: Vec<anp::authentication::DidVerificationRelationship>,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
    seed: &LockedBytes,
) -> Result<(WrappedKey, ExtraKey)> {
    let (verifying, public_multibase) = wrap::seed_to_public(seed);
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
        seed,
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
    generate_agreement_from_seed(
        did,
        fragment,
        label,
        passphrase,
        device_secret,
        argon,
        hardware,
        &seed,
    )
}

/// 同上,但 seed 由调用方给 —— 助记词恢复时协商密钥走这条。
#[allow(clippy::too_many_arguments)] // 见 `generate_extra` 上面那一段
pub fn generate_agreement_from_seed(
    did: &str,
    fragment: &str,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
    seed: &LockedBytes,
) -> Result<(WrappedKey, ExtraKey)> {
    let (public, public_multibase) = wrap::seed_to_x25519_public(seed);
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
        seed,
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

/// 从一个根 seed 推出另外三把(热、设备签名、协商)—— **不落盘**。
///
/// `keygen` 和助记词恢复都走这一段:同一组关系、同一个 `generate_*_from_seed`。
/// 两条路只要分岔一次,同一张纸就会得到两份不同的文档,而纸还在人手上。
///
/// 名字由调用方给,因为**编号从哪来**是两条路唯一该不一样的地方:`keygen`
/// 在"只有根"的文档上算下一个空位,恢复则要按公钥找回文档里那把钥匙原来的
/// 名字(见 [`crate::did::lifecycle::hot_fragment_of`])。
///
/// `hot_fragment` 为 `None` 表示**不要热密钥**:本机文档里的热密钥不是这张
/// 纸推出来的那把(轮换过),硬恢复只会添一把没人引用的钥匙。
///
/// 三把的 `label` 是固定的("hot" / "device-sign" / "device-agreement"),
/// 不取调用方给的那个:同一个助记词在两台机器上恢复,落下的信封除了口令和
/// KDF 参数之外应当**逐字相同**,否则"这是同一把钥匙吗"就得靠比对指纹才能答。
#[allow(clippy::too_many_arguments)] // 与 `generate_*_from_seed` 同一批决定
pub fn derived_extras(
    did: &str,
    hot_fragment: Option<&str>,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
    hardware: HardwareChoice,
    root_seed: &LockedBytes,
) -> Result<Vec<(WrappedKey, ExtraKey)>> {
    let mut derived = Vec::with_capacity(3);

    if let Some(hot_fragment) = hot_fragment {
        derived.push(generate_extra_from_seed(
            did,
            hot_fragment,
            vec![anp::authentication::DidVerificationRelationship::Authentication],
            "hot",
            passphrase,
            device_secret,
            argon,
            hardware,
            &crate::crypto::derive::hot(root_seed)?,
        )?);
    }

    // 设备签名键要**两处都挂**:上游把同时出现在 `authentication` 与
    // `assertionMethod` 读成 `DeviceSigning` 角色。只挂一处会落到热密钥或
    // 恢复密钥的角色上,而那把钥匙就干不了设备断言。
    derived.push(generate_extra_from_seed(
        did,
        crate::did::document::DEVICE_SIGN_FRAGMENT,
        vec![
            anp::authentication::DidVerificationRelationship::Authentication,
            anp::authentication::DidVerificationRelationship::AssertionMethod,
        ],
        "device-sign",
        passphrase,
        device_secret,
        argon,
        hardware,
        &crate::crypto::derive::device_sign(root_seed)?,
    )?);

    derived.push(generate_agreement_from_seed(
        did,
        crate::did::document::DEVICE_AGREEMENT_FRAGMENT,
        "device-agreement",
        passphrase,
        device_secret,
        argon,
        hardware,
        &crate::crypto::derive::device_agreement(root_seed)?,
    )?);

    Ok(derived)
}

/// 从一个助记词熵铸出**四把钥匙**的整套身份。
///
/// 四把的 seed 都从 `root_seed` 推:根就是它本身,热/设备签名/协商各走一条
/// HKDF 域串(见 [`crate::crypto::derive`])。所以一张纸能把整套身份再铸一遍
/// —— 这是 `keygen` 显示 24 个词的唯一理由,算法之外没有第二份备份。
///
/// # 先全算出来,再一起落盘
///
/// 四个信封在写第一个字节之前就全部造完。硬件根不可用这类失败因此**什么都
/// 不留**,而不是留下"两把进去了、两把没有"的半套身份 —— 那种状态下 DID
/// 文档要么缺键、要么指向不存在的键。
///
/// # 这里仍然不写文档
///
/// 和 [`create`] 一样:没有签名的文档写下去只会被误认为已发布。调用方拿到
/// [`Identity::document_keys`] 之后自己构造并签名。
pub fn create_identity(
    layout: &KeydLayout,
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    argon: Argon2Config,
    hardware: HardwareChoice,
    root_seed: &LockedBytes,
) -> Result<Identity> {
    layout.ensure()?;
    let device_secret = device::load_or_create(layout)?;

    let root = generate_from_seed(
        spec,
        label,
        passphrase,
        &device_secret,
        argon,
        hardware,
        root_seed,
    )?;
    let did = root.did.clone();

    // 编号在"只有根"的那份文档上算 —— 新身份的文档里只有 `key-1`,
    // 热密钥因此从 `key-2` 起。已经躺在 `keys/` 里的编号也要算进去:
    // 摘掉一把钥匙不删信封,而重用一个退休过的编号会让两份内容不同的文档
    // 顶同一个 `id`。
    let (_, base) = crate::did::document::build_unsigned(spec, &root.wrapped.verifying_key()?)?;
    let hot_fragment = crate::did::lifecycle::next_hot_fragment(
        &base,
        &did,
        &store::envelope_fragments(layout, &did)?,
    )?;
    let derived = derived_extras(
        &did,
        Some(&hot_fragment),
        passphrase,
        &device_secret,
        argon,
        hardware,
        root_seed,
    )?;

    store::save_new(layout, &root.wrapped)?;
    let mut extras = Vec::with_capacity(derived.len());
    let mut document_keys = Vec::with_capacity(derived.len());
    for (wrapped, key) in derived {
        store::save_new(layout, &wrapped)?;
        extras.push(wrapped);
        document_keys.push(key);
    }

    Ok(Identity { did, root: root.wrapped, extras, document_keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::thumbprint::e1_from_did;
    use crate::did::document::{build_unsigned, build_unsigned_with, ROOT_FRAGMENT};
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
    fn create_identity_mints_four_keys_and_one_document() {
        let dir = std::env::temp_dir().join(format!("keyd-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir.clone());
        let seed = LockedBytes::fill(|bytes| *bytes = [0x07; 32]).unwrap();
        let identity = create_identity(
            &layout,
            &spec(),
            "alice",
            b"pw",
            fast(),
            HardwareChoice::None,
            &seed,
        )
        .unwrap();

        // 四个信封、四个指纹,全都解得开并且属于同一个 DID。
        let mut thumbprints = std::collections::BTreeSet::new();
        for wrapped in std::iter::once(&identity.root).chain(identity.extras.iter()) {
            assert!(thumbprints.insert(wrapped.id.thumbprint.clone()), "two keys collided");
            assert_eq!(wrapped.id.did, identity.did);
            assert_eq!(
                store::load(&layout, &wrapped.id.thumbprint).unwrap().id,
                wrapped.id
            );
        }
        assert_eq!(thumbprints.len(), 4);

        // 编号:根 `key-1`(由 spec 定),热密钥从 `key-2` 起。
        let fragments: Vec<&str> = identity
            .document_keys
            .iter()
            .map(|key| key.fragment.as_str())
            .collect();
        assert_eq!(fragments, ["key-2", "device-sign", "device-agreement"]);

        // 一份文档装得下四把,而且每把挂在它该在的关系下。
        let root = identity.root.verifying_key().unwrap();
        let (did, document) =
            build_unsigned_with(&spec(), &root, identity.document_keys.clone()).unwrap();
        assert_eq!(did, identity.did);
        assert_eq!(document["verificationMethod"].as_array().unwrap().len(), 4);

        let names = |relationship: &str| -> Vec<String> {
            document[relationship]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| {
                    id.as_str()
                        .unwrap()
                        .rsplit('#')
                        .next()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(
            names("authentication"),
            ["key-1", "key-2", "device-sign"],
            "the agreement key must not be able to authenticate"
        );
        assert_eq!(names("assertionMethod"), ["key-1", "device-sign"]);
        assert_eq!(names("keyAgreement"), ["device-agreement"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 同一张纸必须铸出同一套身份 —— 换台机器恢复时这是唯一的依据。
    #[test]
    fn the_same_seed_restores_the_same_four_keys() {
        let mut public = Vec::new();
        for name in ["a", "b"] {
            let dir = std::env::temp_dir()
                .join(format!("keyd-identity-same-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let layout = KeydLayout::at(dir.clone());
            let seed = LockedBytes::fill(|bytes| *bytes = [0x42; 32]).unwrap();

            let identity = create_identity(
                &layout,
                &spec(),
                "alice",
                b"pw",
                fast(),
                HardwareChoice::None,
                &seed,
            )
            .unwrap();
            let mut keys = vec![identity.root.public_multibase.clone()];
            keys.extend(identity.extras.iter().map(|key| key.public_multibase.clone()));
            public.push((identity.did, keys));
            let _ = std::fs::remove_dir_all(&dir);
        }

        // 信封里的密码学材料相同 —— 盐和 nonce 当然每次不同,那不影响身份。
        assert_eq!(public[0], public[1]);
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
