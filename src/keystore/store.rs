//! 信封的落盘与读回。
//!
//! 这一层只做三件事:原子写、按指纹读、以及**确认文件自称的身份**。
//! 密码学不在这里 —— 这里读回来的东西仍然是加密的。

use std::collections::BTreeSet;
use std::fs;

use crate::error::{KeydError, Result};
use crate::keystore::layout::{self, KeydLayout, PUBLIC_FILE_MODE, SECRET_FILE_MODE};
use crate::keystore::record::WrappedKey;

/// 把一个信封写到 `keys/<thumbprint>.json`,权限 0600。
///
/// 已存在就**拒绝**(`KeyExists`)。覆写一个密钥信封是不可逆的:旧的那把
/// seed 只存在于这个文件里,盖掉就是永久丢失。
pub fn save_new(layout: &KeydLayout, wrapped: &WrappedKey) -> Result<()> {
    wrapped.validate()?;
    let path = layout.key_path(&wrapped.id.thumbprint)?;
    if path.exists() {
        return Err(KeydError::KeyExists(wrapped.id.thumbprint.clone()));
    }
    write(layout, wrapped)
}

/// 无条件写。旋转、迁移这类"我知道我在覆盖"的路径才用它。
pub fn write(layout: &KeydLayout, wrapped: &WrappedKey) -> Result<()> {
    wrapped.validate()?;
    let path = layout.key_path(&wrapped.id.thumbprint)?;
    let mut bytes = serde_json::to_vec_pretty(wrapped)?;
    let result = layout::write_atomic(&path, &bytes, SECRET_FILE_MODE);
    // 序列化出来的明文 JSON 里没有密钥材料,但没理由让它多留在内存里。
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

pub fn exists(layout: &KeydLayout, thumbprint: &str) -> bool {
    layout
        .key_path(thumbprint)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// 按指纹读回一个信封,并确认**文件名与文件内容说的是同一把钥匙**。
///
/// 这一条挡的是计划 M1 负例 C 的文件那一面:`cp A.json B.json` 之后,
/// 内容自洽(AAD 当然算得过),但 B 这个位置上是 A 的钥匙。守护进程只要
/// 按下标取钥匙,就会拿 A 的私钥去兑现 B 的 DID —— 必须在这里断掉。
///
/// 报 `Protocol` 而不是 `AadMismatch`:摘要本身没被改,是被搬了家。
/// "改名"和"改头"是两种事故,给两个不同的错才好查。
pub fn load(layout: &KeydLayout, thumbprint: &str) -> Result<WrappedKey> {
    let path = layout.key_path(thumbprint)?;
    if !path.exists() {
        return Err(KeydError::KeyNotFound(thumbprint.to_string()));
    }
    let bytes = layout::read_secret_file(&path)?;
    let wrapped: WrappedKey = serde_json::from_slice(&bytes)
        .map_err(|e| KeydError::Protocol(format!("{} is not a readable envelope: {e}", path.display())))?;

    wrapped.validate()?;
    if wrapped.id.thumbprint != thumbprint {
        return Err(KeydError::Protocol(format!(
            "{} was renamed: it contains {}'s key, not {thumbprint}'s",
            path.display(),
            wrapped.id.thumbprint
        )));
    }
    Ok(wrapped)
}

/// 读出所有信封,按指纹排序。
///
/// 读不懂的文件**不跳过** —— 静默略过等于让用户以为自己的钥匙不见了。
pub fn load_all(layout: &KeydLayout) -> Result<Vec<WrappedKey>> {
    let mut out = Vec::new();
    for path in layout.list_key_paths()? {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KeydError::Protocol(format!("odd envelope filename: {}", path.display())))?;
        out.push(load(layout, stem)?);
    }
    out.sort_by(|a, b| a.id.thumbprint.cmp(&b.id.thumbprint));
    Ok(out)
}

/// 磁盘上属于某个 DID 的全部信封。
///
/// **不能只看 `keys/<DID 的 e1_ 段>.json`。** 那个文件名是**绑定密钥**的
/// 指纹算出来的,而一个 DID 可以合法地再挂热密钥和恢复密钥(见
/// [`crate::did::lifecycle`])—— 它们的信封是按各自的公钥指纹命名的,跟
/// DID 的最后一段对不上。只按文件名找,那两把钥匙就等于不存在。
pub fn envelopes_for_did(layout: &KeydLayout, did: &str) -> Result<Vec<WrappedKey>> {
    Ok(load_all(layout)?
        .into_iter()
        .filter(|wrapped| wrapped.id.did == did)
        .collect())
}

/// 本机为某个 DID 铸过的钥匙的 fragment —— **包括已经摘掉的**。
///
/// 摘钥匙不删信封(见 [`crate::ops::keys::remove_key`]),所以磁盘上的信封
/// 是"这个 DID 在本机用过哪些编号"的记录,而文档只是"现在还认哪些"。这两个
/// 集合**不一样**,而且差的正是危险的那部分:编号分配必须看前者。
///
/// 只看文档的话,摘掉一把钥匙会把它的编号放回池子里,下一次加钥匙就会重新
/// 发出同一个编号 —— 而那个编号可能正被一把**已经泄露、所以被摘掉**的
/// 私钥用着。任何缓存过旧文档的验证方都会把旧钥匙的签名当成有效签名。
pub fn envelope_fragments(layout: &KeydLayout, did: &str) -> Result<BTreeSet<String>> {
    let prefix = format!("{did}#");
    Ok(envelopes_for_did(layout, did)?
        .into_iter()
        .filter_map(|wrapped| wrapped.id.kid.strip_prefix(&prefix).map(str::to_string))
        .collect())
}

/// 把一个 DID(可选再指定一个 fragment)解析成**唯一一份**信封。
///
/// 三条规则,每一条都是为了不给调用方一个可以静默猜错的地方:
///
/// 1. 给了 fragment:就要那一个。找不到就是找不到,不许退回到别的。
/// 2. 没给 fragment,而绑定密钥在这台机器上:**就是它**。绑定密钥是 DID
///    自己的一部分(最后一段就是它的指纹),所以它是这个 DID 的**默认**
///    那把 —— 而不是"碰巧只有一把"的兜底。挂上热密钥之后老调用方不会
///    因为多了一把钥匙就换了把钥匙来签名。
/// 3. 没给 fragment,绑定密钥也不在,而只有一把:用它。
///
/// 剩下"好几把、还都不是绑定密钥"的情况**报错**,列出候选。挑一把最近的、
/// 最小的或者随便哪一把都是在替调用方决定"用哪把钥匙签名",而签名用的是
/// 哪把钥匙决定了签名能被谁验过 —— 这种事不许靠猜。
///
/// `kid` 是**一个 fragment**(`key-2`、`recovery-1`),不是完整的
/// `did#fragment`。磁盘上的 `KeyId.kid` 是完整的那个,这里拼一次再比 ——
/// 拼接发生在**一个地方**,而不是散在每一个调用点。
pub fn resolve(layout: &KeydLayout, did: &str, kid: Option<&str>) -> Result<WrappedKey> {
    let candidates = envelopes_for_did(layout, did)?;
    if candidates.is_empty() {
        return Err(KeydError::KeyNotFound(did.to_string()));
    }

    if let Some(kid) = kid {
        let wanted = format!("{did}#{kid}");
        return candidates
            .into_iter()
            .find(|wrapped| wrapped.id.kid == wanted)
            .ok_or_else(|| {
                KeydError::KeyNotFound(format!(
                    "{did} has no key named {kid:?}; the ones it has are listed by `anpio-key list`"
                ))
            });
    }

    let binding = binding_thumbprint(did);
    if let Some(thumbprint) = binding {
        if let Some(found) = candidates
            .iter()
            .find(|wrapped| wrapped.id.thumbprint == thumbprint)
        {
            return Ok(found.clone());
        }
    }

    match candidates.len() {
        1 => Ok(candidates.into_iter().next().expect("checked the length")),
        _ => {
            let mut names: Vec<&str> =
                candidates.iter().map(|wrapped| wrapped.id.kid.as_str()).collect();
            names.sort_unstable();
            Err(KeydError::Protocol(format!(
                "{did} has {} keys on this machine and none of them is its binding key, \
                 so which one to use has to be said out loud: {}",
                names.len(),
                names.join(", ")
            )))
        }
    }
}

/// `did:wba:...:e1_<指纹>` → `<指纹>`。解不出 `e1_` 段的 DID 没有绑定密钥。
fn binding_thumbprint(did: &str) -> Option<String> {
    crate::did::parse::parse_did_wba(did)
        .ok()
        .and_then(|parts| parts.e1_segment().map(str::to_string))
}

/// 删掉一个信封。这是不可逆的 —— 调用方负责先确认用户真的要这么做。
pub fn delete(layout: &KeydLayout, thumbprint: &str) -> Result<()> {
    let path = layout.key_path(thumbprint)?;
    fs::remove_file(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeydError::KeyNotFound(thumbprint.to_string())
        } else {
            KeydError::Io(e)
        }
    })
}

/// 写一份可公开的 DID 文档(0644)。
pub fn write_did_document(layout: &KeydLayout, did: &str, doc: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(doc)?;
    let result = layout::write_atomic(&layout.did_path(did), &bytes, PUBLIC_FILE_MODE);
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

pub fn read_did_document(layout: &KeydLayout, did: &str) -> Result<serde_json::Value> {
    let path = layout.did_path(did);
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeydError::KeyNotFound(did.to_string())
        } else {
            KeydError::Io(e)
        }
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// 读一份 DID 文档的**原始字节** —— 就是 `publish` 写下去的那一份。
///
/// 和 [`read_did_document`] 的区别是它不经过 `serde_json::Value`:那份文档是
/// 一件**签好名的成品**,它的字节就是被签的那些字节,而 `Value` 一来一回会
/// 把键重排(默认的 `Map` 是有序的),交出去就不再是发布出去的那一份了。
/// 调用方要内联它、要拿它和服务端手里那份比,所以这里给的是原文。
///
/// 仍然解析一遍 —— 不是为了用它,是为了**不把一份读不懂的文件当文档交出去**。
pub fn read_did_document_bytes(layout: &KeydLayout, did: &str) -> Result<Vec<u8>> {
    let path = layout.did_path(did);
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeydError::KeyNotFound(did.to_string())
        } else {
            KeydError::Io(e)
        }
    })?;
    serde_json::from_slice::<serde_json::Value>(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public, SealRequest};

    fn fast() -> Argon2Config {
        Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    fn layout(name: &str) -> KeydLayout {
        let dir = std::env::temp_dir().join(format!("keyd-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let l = KeydLayout::at(dir);
        l.ensure().unwrap();
        l
    }

    fn envelope(thumbprint: &str) -> WrappedKey {
        let did = format!("did:wba:example.com:user:alice:{thumbprint}");
        envelope_for(&did, &format!("{did}#key-1"), thumbprint)
    }

    /// 同一个 DID 上的第 N 把钥匙。
    fn envelope_for(did: &str, kid: &str, thumbprint: &str) -> WrappedKey {
        let seed = LockedBytes::fill(|d| *d = [0x11; 32]).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let device = LockedBytes::fill(|d| *d = [0x22; 32]).unwrap();
        seal(SealRequest {
            id: KeyId { did: did.to_string(), kid: kid.to_string(), thumbprint: thumbprint.into() },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "alice".into(),
            passphrase: b"pw",
            device_secret: &device,
            seed: &seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap()
    }

    #[test]
    fn save_load_roundtrip() {
        let l = layout("roundtrip");
        let w = envelope("e1_one");
        save_new(&l, &w).unwrap();

        let back = load(&l, "e1_one").unwrap();
        assert_eq!(back.id.thumbprint, "e1_one");
        assert_eq!(back.public_multibase, w.public_multibase);
        assert!(back.verify_aad().is_ok());

        let _ = fs::remove_dir_all(l.root());
    }

    /// 信封是"这个 DID 用过哪些编号"的记录 —— 它必须包含**已经摘掉**的钥匙。
    ///
    /// 编号分配依赖这条:文档会随着摘钥匙忘掉一个编号,信封不会。
    #[test]
    fn envelope_fragments_include_keys_that_were_removed() {
        let l = layout("fragments");
        let did = "did:wba:example.com:user:alice:e1_one";
        // 绑定密钥 + 两把热密钥;热密钥那把是被摘掉之后才留下的信封。
        save_new(&l, &envelope_for(did, &format!("{did}#key-1"), "e1_one")).unwrap();
        save_new(&l, &envelope_for(did, &format!("{did}#key-2"), "e1_two")).unwrap();
        save_new(&l, &envelope_for(did, &format!("{did}#recovery-1"), "e1_three")).unwrap();
        // 别人的 DID 不该混进来。
        save_new(&l, &envelope("e1_other")).unwrap();

        let fragments = envelope_fragments(&l, did).unwrap();
        let expected: BTreeSet<String> =
            ["key-1", "key-2", "recovery-1"].iter().map(|s| s.to_string()).collect();
        assert_eq!(fragments, expected);

        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn save_new_refuses_to_overwrite_a_live_key() {
        let l = layout("overwrite");
        save_new(&l, &envelope("e1_one")).unwrap();
        assert!(matches!(
            save_new(&l, &envelope("e1_one")),
            Err(KeydError::KeyExists(_))
        ));
        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn missing_key_is_key_not_found() {
        let l = layout("missing");
        assert!(matches!(load(&l, "e1_nope"), Err(KeydError::KeyNotFound(_))));
        let _ = fs::remove_dir_all(l.root());
    }

    /// 计划 M1 负例 C 的文件那一面:把 A 的信封复制成 B 的名字。
    #[test]
    fn a_renamed_envelope_is_refused_even_though_its_aad_still_checks_out() {
        let l = layout("renamed");
        let a = envelope("e1_aaa");
        save_new(&l, &a).unwrap();

        let b_path = l.key_path("e1_bbb").unwrap();
        fs::copy(l.key_path("e1_aaa").unwrap(), &b_path).unwrap();
        fs::set_permissions(&b_path, fs::Permissions::from_mode(0o600)).unwrap();

        // 内容本身是自洽的 —— 这正是危险之处。
        let raw: WrappedKey = serde_json::from_slice(&fs::read(&b_path).unwrap()).unwrap();
        assert!(raw.verify_aad().is_ok(), "the copied file is internally consistent");

        // 但按 B 的名字取,必须被拒。
        assert!(matches!(load(&l, "e1_bbb"), Err(KeydError::Protocol(_))));

        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn load_all_refuses_to_silently_skip_a_broken_file() {
        let l = layout("broken");
        save_new(&l, &envelope("e1_aaa")).unwrap();
        fs::write(l.key_path("e1_bad").unwrap(), b"{ not json").unwrap();

        assert!(
            load_all(&l).is_err(),
            "a key file we cannot read must not be silently ignored"
        );
        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn load_all_is_sorted_and_complete() {
        let l = layout("all");
        for t in ["e1_ccc", "e1_aaa", "e1_bbb"] {
            save_new(&l, &envelope(t)).unwrap();
        }
        let all = load_all(&l).unwrap();
        let stems: Vec<_> = all.iter().map(|w| w.id.thumbprint.as_str()).collect();
        assert_eq!(stems, ["e1_aaa", "e1_bbb", "e1_ccc"]);
        let _ = fs::remove_dir_all(l.root());
    }

    use std::os::unix::fs::PermissionsExt;

    // ————————————————————————————————————————————————————————————————————
    // 一个 DID 上不止一把钥匙之后,`resolve` 就是"用哪把签名"的答案。
    // 每一条规则都对应一种**会静默签错钥匙**的失败方式。
    // ————————————————————————————————————————————————————————————————————

    const DID: &str = "did:wba:example.com:user:alice:e1_bind";

    /// 只给 DID:选**绑定密钥**,而不是碰巧也在的那把热密钥。
    ///
    /// 挂上热密钥之后,老调用方手里还是只有那个 DID。这时候要是按
    /// "钥匙数量"之类的规则去挑,他们的签名就会在某一天悄悄换成另一把钥匙
    /// 签的 —— 而验签方那边只会看到一个"验不过"。
    #[test]
    fn the_binding_key_is_the_default_even_when_a_hot_key_is_present() {
        let l = layout("resolve-default");
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-1"), "e1_bind")).unwrap();
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-2"), "e1_hot")).unwrap();

        let picked = resolve(&l, DID, None).unwrap();
        assert_eq!(picked.id.kid, format!("{DID}#key-1"));
        assert_eq!(picked.id.thumbprint, "e1_bind");

        let _ = fs::remove_dir_all(l.root());
    }

    /// 给了 fragment:**就**是那一把,不许退回绑定密钥。
    #[test]
    fn an_explicit_fragment_selects_exactly_that_key() {
        let l = layout("resolve-explicit");
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-1"), "e1_bind")).unwrap();
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-2"), "e1_hot")).unwrap();

        let picked = resolve(&l, DID, Some("key-2")).unwrap();
        assert_eq!(picked.id.thumbprint, "e1_hot");

        // 不存在的那一个:找不到就是找不到,而不是"那用默认的吧"。
        let e = resolve(&l, DID, Some("key-9")).unwrap_err();
        assert!(matches!(e, KeydError::KeyNotFound(_)), "{e}");

        let _ = fs::remove_dir_all(l.root());
    }

    /// 绑定密钥不在本机、又有好几把备选:**报错**,不替调用方挑。
    ///
    /// 这是唯一一处必须失败的地方 —— 挑错钥匙等于把一个签名挂到另一把
    /// 验证密钥名下,而验签方没有义务接受。
    #[test]
    fn two_candidates_and_no_binding_key_is_an_error_not_a_guess() {
        let l = layout("resolve-ambiguous");
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-2"), "e1_hot")).unwrap();
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-3"), "e1_warm")).unwrap();

        let error = resolve(&l, DID, None).unwrap_err().to_string();
        assert!(error.contains("key-2"), "{error} must name the candidates");
        assert!(error.contains("key-3"), "{error} must name the candidates");

        // 但指到具体那一个就没问题。
        assert!(resolve(&l, DID, Some("key-3")).is_ok());

        let _ = fs::remove_dir_all(l.root());
    }

    /// 只有一把、又不是绑定密钥:用它。这里没有可挑的余地,报错只是折腾人。
    #[test]
    fn a_single_non_binding_key_is_used() {
        let l = layout("resolve-single");
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-2"), "e1_hot")).unwrap();
        assert_eq!(resolve(&l, DID, None).unwrap().id.kid, format!("{DID}#key-2"));
        let _ = fs::remove_dir_all(l.root());
    }

    /// `envelopes_for_did` 不能只看文件名 —— 热密钥的文件名是它**自己的**
    /// 公钥指纹,和 DID 最后一段对不上。
    #[test]
    fn envelopes_for_a_did_finds_keys_whose_filename_is_not_the_did() {
        let l = layout("resolve-siblings");
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-1"), "e1_bind")).unwrap();
        save_new(&l, &envelope_for(DID, &format!("{DID}#key-2"), "e1_hot")).unwrap();
        save_new(&l, &envelope("e1_other")).unwrap();

        let found = envelopes_for_did(&l, DID).unwrap();
        assert_eq!(found.len(), 2, "the hot key's file is named after its own thumbprint");

        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn did_documents_land_world_readable() {
        let l = layout("did");
        let did = "did:wba:example.com:user:alice:e1_one";
        write_did_document(&l, did, &serde_json::json!({"id": did})).unwrap();

        let mode = fs::metadata(l.did_path(did)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PUBLIC_FILE_MODE);
        assert_eq!(read_did_document(&l, did).unwrap()["id"], did);

        let _ = fs::remove_dir_all(l.root());
    }
}
