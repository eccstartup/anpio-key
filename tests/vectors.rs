//! 外部标准的测试向量,外加一条兄弟实现的 —— 计划 §十。
//!
//! # 为什么单开一个文件
//!
//! 单元测试问的是"我们按自己的理解做对了吗";这一份问的是另一个问题:
//! **"我们和外面的世界用的是同一个标准吗"**。两者的失败含义完全不同 ——
//! 前者红了是代码写错了,后者红了是**我们和互联网上所有人算出来的东西不一样**,
//! 而那种错误在自己的代码里怎么读都读不出来:自洽、可复现、测试全绿,
//! 只是别人验不过。
//!
//! # 这些向量是从哪儿来的
//!
//! `tests/vectors/*.json` 里每一个字节都是有出处的(写在各自的 `_source`
//! 字段);不是我照着记忆打的。出处有两类,而**失败时该怀疑谁,取决于它是哪
//! 一类**:
//!
//! - **RFC 正文的抄本**(`rfc*.json`)。向量是权威文本,所以**它红了,先怀疑
//!   实现**。改向量让测试变绿,正好把这个文件存在的理由抹掉。
//! - **一个兄弟实现自己算出来的值**(`anp_sdk_*.json`)。它红了是**两个实现
//!   分家了**,得先问是谁动了 —— 期望值那一串在别人家的测试里也是断言,它有
//!   可能才是对的一方。去两边的仓库里各读一遍,而不是挑一边改。
//!
//! 同一件事也解释了为什么这里缺了几样东西。RFC 9421 附录 B 只有一条同时
//! 满足"Ed25519"(确定性,签名可复现)和"覆盖集非空"(本实现按 §M3 拒绝空
//! 覆盖集);其余要么是 RSA-PSS,要么覆盖集是空的。RFC 8032 §7.1 的 TEST 1024
//! 有——它那 1023 字节的消息是从 RFC 里抽的,不是打的。凡是不能逐字符复现的,
//! 与其写一个我记得的近似值,不如不写。

use anpio_key::crypto::hygiene::LockedBytes;
use anpio_key::crypto::thumbprint::e1_segment;
use anpio_key::keystore::KeyId;
use anpio_key::sign::{LockedSigningKey, Signer};
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use serde_json::Value;

// ————————————————————————————————————————————————————————————
// 读向量
// ————————————————————————————————————————————————————————————

/// 从 `tests/vectors/` 读一份向量。路径按 `CARGO_MANIFEST_DIR` 拼,
/// 不按当前工作目录 —— `cargo test` 的工作目录不保证是 crate 根。
fn vectors(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key:?} in {value}"))
        .to_string()
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {key:?}"))
}

/// 在数组里按名字找一条。
fn named<'a>(rows: &'a [Value], key: &str, wanted: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(wanted))
        .unwrap_or_else(|| panic!("no row with {key} = {wanted:?}"))
}

/// `"9d61b1…"` → 字节。长度是奇数或者有非十六进制字符,就是向量文件坏了。
fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("a hex digit"))
        .collect()
}

/// JWK 与指纹用的是**无填充的 base64url**。
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 9421 的签名头用的是**带填充的标准 base64** —— 和上面那个不是一回事。
fn b64_std(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 把一个 seed 装成一把 `Signer`。身份坐标是占位的 —— 这些向量测的是
/// 签名算法,不是 did:wba 的路径拼接。
fn key_from(seed: &[u8]) -> LockedSigningKey {
    let mut seed: [u8; 32] = seed.try_into().expect("an Ed25519 seed is 32 bytes");
    let id = KeyId {
        did: "did:wba:example.com:vectors:e1_vector".into(),
        kid: "did:wba:example.com:vectors:e1_vector#key-1".into(),
        thumbprint: "e1_vector".into(),
    };
    LockedSigningKey::from_seed(id, LockedBytes::new(&mut seed).unwrap()).expect("from_seed")
}

fn canonical(value: &Value) -> String {
    String::from_utf8(serde_json_canonicalizer::to_vec(value).expect("canonicalize"))
        .expect("canonical JSON is UTF-8")
}

// ————————————————————————————————————————————————————————————
// RFC 8032 —— 我们签出来的就是 Ed25519 吗
// ————————————————————————————————————————————————————————————

/// **§7.1 的每一条都必须逐字节复现。**
///
/// 这一条守的是"我们拿到的确实是 RFC 8032 的 Ed25519"。它挡的是一整类看起来
/// 很对、其实不是同一个算法的实现:Ed25519ph(先哈希再签)、Ed25519ctx(带域
/// 分离),或者自己发明的某个变体。它们每一个都能通过"签出来能验过"这种自洽
/// 测试 —— 自己签自己验当然过得去 —— 只有在对着标准向量逐字节比的时候才现原形。
///
/// 消息长度 0、1、2、64、1023 各一条不是凑数:长度是最容易在边界上走偏的地方,
/// 而 1023 那条还顺带把"跨块"这件事盖住了。
#[test]
fn rfc8032_ed25519_signatures_come_out_byte_for_byte() {
    let file = vectors("rfc8032_ed25519.json");
    let rows = array(&file, "vectors");
    let cases: Vec<&Value> = rows
        .iter()
        .filter(|row| string(row, "kind") == "plain")
        .collect();
    assert!(cases.len() >= 5, "expected all of the section 7.1 vectors");

    for case in cases {
        let name = string(case, "name");
        let seed = unhex(&string(case, "secret_key"));
        let public = unhex(&string(case, "public_key"));
        let message = unhex(&string(case, "message"));
        let expected = unhex(&string(case, "signature"));

        assert_eq!(seed.len(), 32, "{name}: an Ed25519 seed is 32 bytes");
        assert_eq!(expected.len(), 64, "{name}: an Ed25519 signature is 64 bytes");

        let key = key_from(&seed);

        // 先钉住"公钥确实是这个 seed 推出来的" —— 否则下面那条比的可能是两把
        // 不同的钥匙,而它会以"签名不对"的样子失败,把人指错方向。
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            public,
            "{name}: the public key has to come from this seed"
        );
        assert_eq!(
            key.sign(&message).expect("sign").to_vec(),
            expected,
            "{name}: the signature has to be the RFC's, byte for byte"
        );

        // 而且我们自己的验签得认它 —— 签名路径和验签路径不能各错一半,
        // 那种组合下"签出来验得过"这句自洽的话就不再成立。
        let signature: [u8; 64] = expected.as_slice().try_into().unwrap();
        assert!(key.verify(&message, &signature), "{name}: our own verifier");
    }
}

/// **Ed25519ph 不是我们做的那件事 —— 而且两条路会给出不同的签名。**
///
/// 这一条是上一条的补集。"我们的签名等于 §7.1 的值"本身还排除不掉"我们碰巧
/// 两条路都对",所以这里把 ph 的向量摆出来,断言我们**不**产出它。
///
/// §7.3 的 ph 向量与 §7.1 的 `TEST SHA(abc)` 用的是**同一把钥匙**:后者签的是
/// 消息 `SHA-512("abc")`,前者签的是 `abc` 本身。两条签名不同,差别只可能来自
/// 算法(ph 多一层域分离前缀),不可能来自密钥。于是"我们产出哪一个"就成了一道
/// 可以判定的问题。
#[test]
fn rfc8032_ed25519ph_is_not_what_we_produce() {
    let file = vectors("rfc8032_ed25519.json");
    let rows = array(&file, "vectors");
    let ph = named(rows, "kind", "ph");
    let sha = named(rows, "name", "TEST SHA(abc)");

    // 两条向量的钥匙必须是同一把,否则下面的对比什么也证明不了。
    assert_eq!(string(ph, "secret_key"), string(sha, "secret_key"));
    assert_eq!(string(ph, "public_key"), string(sha, "public_key"));

    let seed = unhex(&string(ph, "secret_key"));
    let message = unhex(&string(ph, "message"));
    assert_eq!(message, b"abc", "the ph vector signs the literal bytes abc");

    let key = key_from(&seed);
    assert_ne!(
        key.sign(&message).expect("sign").to_vec(),
        unhex(&string(ph, "signature")),
        "this is an Ed25519ph signature; Ed25519ph is a different algorithm"
    );

    // 而那条预哈希的向量我们是复现得出来的。两件事一起看才说得清:我们做的是
    // 普通 Ed25519,哈希只是好端端喂进来的消息内容。
    let prehashed = unhex(&string(sha, "message"));
    assert_eq!(
        prehashed,
        Sha512::digest(b"abc").to_vec(),
        "TEST SHA(abc) must be SHA-512 of the literal bytes abc"
    );
    assert_eq!(
        key.sign(&prehashed).expect("sign").to_vec(),
        unhex(&string(sha, "signature")),
        "a pre-hashed message is signed as an ordinary Ed25519 message"
    );
}

// ————————————————————————————————————————————————————————————
// RFC 7638 / RFC 8037 —— 那个 e1_ 段是怎么来的
// ————————————————————————————————————————————————————————————

/// **先复现 RFC 自己的算例,再看同一套步骤用在 Ed25519 上对不对。**
///
/// RFC 7638 §3.1 是唯一一处把中间结果全印出来的地方:规范化后的 JSON、每一个
/// UTF-8 字节、每一个摘要字节、最后的指纹。所以它是**方法**的锚 —— 一个独立
/// 实现只要复现得出它,就说明那几步(只取必需成员、按成员名字典序、无空白、
/// UTF-8、SHA-256、base64url 无填充)一步步都对。
///
/// 这里连 `utf8_octets` 都比。只比最后的指纹是不够的:中间任何一步换来换去,
/// 都可能凑出一个"看起来对了"的摘要,而 373 字节的输入错一位就全变 ——
/// 逐字节比才把中间每一步真正钉住。
#[test]
fn the_rfc7638_method_reproduces_its_own_worked_example() {
    let file = vectors("rfc7638_jwk_thumbprint.json");

    for case in array(&file, "cases") {
        let name = string(case, "name");
        let members = case
            .get("required_members")
            .and_then(Value::as_object)
            .expect("required_members is an object");

        // RFC 7638 §3.2 的第一步:只取必需成员,按成员名字典序。
        let mut ordered: Vec<(&str, &str)> = members
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str().expect("a string member")))
            .collect();
        ordered.sort_by_key(|(key, _)| *key);

        let canonical = format!(
            "{{{}}}",
            ordered
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).unwrap(),
                    serde_json::to_string(value).unwrap()
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(canonical, string(case, "canonical"), "{name}: canonical JSON");

        let octets = canonical.into_bytes();
        // RFC 8037 只印了指纹,没印这个 key 的字节数组 —— 所以那一格只有
        // RFC 7638 的算例有。缺了就不比,而不是补一个我自己算的进去:
        // 自己算出来的"期望值"和实现错在同一处时,它会安安静静地变绿。
        if let Some(printed) = case.get("utf8_octets") {
            let expected: Vec<u8> = printed
                .as_array()
                .expect("an array of bytes")
                .iter()
                .map(|byte| byte.as_u64().expect("a byte") as u8)
                .collect();
            assert_eq!(octets, expected, "{name}: every UTF-8 octet");
        }

        let digest = Sha256::digest(&octets);
        assert_eq!(
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            string(case, "sha256_hex"),
            "{name}: the SHA-256 digest"
        );
        assert_eq!(
            b64url(&digest),
            string(case, "thumbprint"),
            "{name}: base64url, unpadded"
        );
    }
}

/// **我们算出的 `e1_` 段,就是 RFC 8037 印出来的那个指纹。**
///
/// 这一条把两份向量接在一起:RFC 8032 §7.1 TEST 1 的**公钥**,配上 RFC 8037
/// 附录 A.3 印出来的**指纹**。中间那一整条链 —— 公钥 → 指纹 → `e1_` 段 ——
/// 全是我们自己的代码,而两端的值都来自 RFC。
///
/// 这是整个文件里最接近生产路径的一条:`e1_` 段是 DID 的最后一段,它错了不会
/// 有任何明显的报错,只会得到一个谁都不认识的 DID。
#[test]
fn the_ed25519_thumbprint_is_the_one_rfc8037_published() {
    let signatures = vectors("rfc8032_ed25519.json");
    let public: [u8; 32] = unhex(&string(named(array(&signatures, "vectors"), "name", "TEST 1"), "public_key"))
        .try_into()
        .unwrap();
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).expect("a valid public key");

    let thumbprints = vectors("rfc7638_jwk_thumbprint.json");
    let case = array(&thumbprints, "cases")
        .iter()
        .find(|case| string(case, "name").contains("Ed25519"))
        .expect("the Ed25519 thumbprint case");

    // 两份 RFC 说的必须是同一把钥匙 —— 这条不成立的话,下面那条比的就是
    // 两个不同的东西,而它照样会是绿的。
    let listed_x = case
        .get("required_members")
        .and_then(|members| members.get("x"))
        .and_then(Value::as_str)
        .expect("the x member");
    assert_eq!(
        b64url(&public),
        listed_x,
        "RFC 8037 A.3 and RFC 8032 7.1 must be talking about the same key"
    );

    assert_eq!(
        e1_segment(&verifying).expect("the e1 segment"),
        string(case, "did_binding_segment"),
        "our e1_ segment has to be RFC 8037's own published thumbprint"
    );
}

// ————————————————————————————————————————————————————————————
// 别人的实现 —— 同一把钥匙,两边算出来的 `e1_` 段是不是同一串
// ————————————————————————————————————————————————————————————

/// **一个兄弟实现自己算出来的 `e1_` 段,我们必须得出同一串。**
///
/// 上面几条把我们的指纹钉在 RFC 上;这一条钉的是**互操作**,而且是往下游一
/// 格。awiki 那套东西(connectx 走的正是它)拿 `anp-sdk` 的 `ed25519Fingerprint`
/// 算 DID,keyd 走的是上游 `anp` 的 `compute_multikey_fingerprint` —— 两边必须
/// 是同一串字节,否则同一个身份在客户端和在服务端会是两个 DID,而**它们各自
/// 看自己都是对的**:自洽、可复现、测试全绿,只是对不上。
///
/// 它和上面几条的失败含义不一样,见文件头:这一条红了是"两个实现分家了",
/// 期望值那串在 `anp-sdk` 里也是断言,它有可能才是对的一方。所以修法是去两个
/// 仓库里各读一遍,不是挑一边改。
///
/// 中间几步也逐项比。只比最后那 46 个字符的话,两边各错一处、恰好抵消,看上去
/// 照样是绿的 —— 而那正是这类分家最常见的形态。
#[test]
fn the_e1_segment_is_the_one_the_sibling_implementation_derives() {
    let file = vectors("anp_sdk_ed25519_fingerprint.json");

    let seed: [u8; 32] = unhex(&string(&file, "seed_hex"))
        .as_slice()
        .try_into()
        .expect("an Ed25519 seed is 32 bytes");
    let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(
        verifying.to_bytes().to_vec(),
        unhex(&string(&file, "public_hex")),
        "the seed has to be the one the sibling derives this public key from"
    );

    // 指纹的输入(RFC 7638 的 JWK)和它的规范化 —— 一步都不许歪。
    let members = file.get("required_members").expect("required_members");
    let jwk = serde_json::json!({
        "crv": string(members, "crv"),
        "kty": string(members, "kty"),
        "x": string(members, "x"),
    });
    assert_eq!(
        b64url(&verifying.to_bytes()),
        string(members, "x"),
        "the JWK's x member is the public key in unpadded base64url"
    );
    assert_eq!(canonical(&jwk), string(&file, "canonical"), "the canonical JWK");

    let digest = Sha256::digest(string(&file, "canonical").as_bytes());
    assert_eq!(
        digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        string(&file, "sha256_hex"),
        "the SHA-256 of that canonical JSON"
    );

    // 最后才是我们自己那一层。前面几项是它的输入,它们先对了,这一条才说明
    // 问题 —— 否则它红的时候看不出是拼装错了还是上游算错了。
    assert_eq!(
        e1_segment(&verifying).expect("the e1 segment"),
        string(&file, "did_binding_segment"),
        "our e1_ segment has to be the one anp-sdk asserts"
    );
}

// ————————————————————————————————————————————————————————————
// RFC 9421 —— 签名基长什么样
// ————————————————————————————————————————————————————————————

/// **附录 B.2.6 的签名基逐字符比对,而它的签名要签得出来。**
///
/// 附录 B 里只有 B.2.6 同时满足两个条件:算法是 Ed25519(确定性,签名可复现),
/// 覆盖集非空(本实现按 §M3 拒绝空覆盖集)。其余各条要么是 RSA-PSS —— 每次
/// 签出来的都不一样,只能验不能比 —— 要么覆盖集是空的。
///
/// 它一次钉住三件事:
///
/// 1. **覆盖集的解析。** 基里 `@signature-params` 那一行括号内的列表是 RFC 9421
///    规定的权威声明。我们的解析器要从这段来自 RFC 的文本里认出那六个分量。
/// 2. **签名基的形状。** 每行是 `"分量": 值`、行间一个 `\n`、**末尾没有换行**。
///    最后一条是 §2.5 的 ABNF 明写的
///    (`signature-base = *( signature-base-line LF ) signature-params-line`),
///    而多一个尾换行会让整份签名基变样,两边各算各的谁也发现不了。
/// 3. **签名的编码。** 签名是带填充的标准 base64,和指纹那种无填充的 base64url
///    不是一回事。两者混用的症状是"只在某些长度下出错"—— 因为只有长度是 3 的
///    倍数时填充才恰好为空。
#[test]
fn the_rfc9421_signature_base_is_reproduced_character_for_character() {
    use anpio_key::sign::rfc9421::verify_covered_set;

    let file = vectors("rfc9421_appendixB.json");
    let base = string(&file, "signature_base");
    let expected: Vec<String> = array(&file, "covered_components")
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();

    // ① 形状。
    assert!(
        !base.ends_with('\n'),
        "the base ends at the parameters line, with no trailing newline"
    );
    assert_eq!(
        base.lines().count(),
        expected.len() + 1,
        "one line per covered component, plus the parameters line"
    );
    let lines: Vec<&str> = base.lines().collect();
    let (parameters, components) = lines.split_last().expect("at least the parameters line");
    assert!(parameters.starts_with("\"@signature-params\": ("), "{parameters:?}");
    for line in components {
        assert!(line.starts_with('"'), "a quoted component id: {line:?}");
        assert!(line.contains("\": "), "a colon and a space: {line:?}");
    }

    // ② 覆盖集的解析 —— 用的是 RFC 印出来的那行文本。
    assert_eq!(
        verify_covered_set(&base, &expected).expect("the RFC's own base must parse"),
        expected
    );

    // 而多要一个它没覆盖的分量,就得被拒 —— 否则上面那条只证明了
    // "这个函数收下了它",没证明它真的在看覆盖集。
    let mut more = expected.clone();
    more.push("content-digest".into());
    assert!(
        verify_covered_set(&base, &more).is_err(),
        "a component the base does not cover has to be refused"
    );

    // ③ 签名。密钥来自 RFC 自己的 JWK(`d` 就是 seed)。
    let key = file.get("key").expect("key");
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(string(key, "seed_b64url"))
        .expect("the RFC's seed");
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(string(key, "public_b64url"))
        .expect("the RFC's public key");

    let signing = key_from(&seed);
    assert_eq!(
        signing.verifying_key().to_bytes().to_vec(),
        public,
        "the RFC's key pair must be self-consistent before we sign with it"
    );
    assert_eq!(
        b64_std(&signing.sign(base.as_bytes()).expect("sign")),
        string(&file, "signature_b64"),
        "the signature over the RFC's own base has to be the RFC's own signature"
    );

    // ④ `Signature-Input` 里那份列表必须和签名基里的逐字相同 ——
    //    它们本来就是同一个值的两种呈现,而验签方比对的就是前者。
    let input = string(&file, "signature_input");
    let list_of = |text: &str| {
        text.split_once('(')
            .expect("an opening paren")
            .1
            .rsplit_once(')')
            .expect("a closing paren")
            .0
            .to_string()
    };
    assert_eq!(list_of(&input), list_of(parameters));
}

// ————————————————————————————————————————————————————————————
// RFC 8785 —— AAD 和指纹都建在这个规范化上
// ————————————————————————————————————————————————————————————

/// **键按 UTF-16 码元排序,而不是按码点。**
///
/// 这是整个文件里最要紧的一条。JCS 的排序规则是"按 UTF-16 码元的值",而大多数
/// 语言的自然排序是按码点 —— 对 BMP 之内的字符两者给出同样的答案,所以随便测
/// 几个欧洲字母都会绿。差别只在有非 BMP 字符(U+FFFF 以上)时出现。
///
/// RFC 8785 §3.2.3 给的那条向量恰好把两者分开:它同时有 U+1F600(emoji,在
/// UTF-16 里是代理对 `D83D DE00`)和 U+FB33。
///
/// - UTF-16 码元序:`D83D` < `FB33` → emoji 在前(**RFC 的答案**)
/// - 码点序:`FB33` < `1F600` → emoji 在后
///
/// 所以这条向量红了,含义是"某个 JSON 库的排序不是 JCS 的排序"—— 而信封的 AAD
/// 正是建在这份规范化上的,两边稍微不一致就会变成"这份备份在另一台机器上打不开"。
#[test]
fn jcs_sorts_property_names_by_utf16_code_units() {
    let file = vectors("rfc8785_jcs.json");
    let sorting = file.get("sorting").expect("sorting");
    let input: Value =
        serde_json::from_str(&string(sorting, "input_source")).expect("the input is JSON");
    let expected: Vec<String> = array(sorting, "expected_property_order")
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();

    let ordered = top_level_key_order(&canonical(&input));
    assert_eq!(ordered, expected, "canonical output was {}", canonical(&input));

    // 这条向量值不值得留,取决于两种顺序是不是真的不一样。不成立的话它什么都
    // 守不住,而那种"守着一个恒真的东西"的测试比没有更糟:它看起来在岗。
    let mut by_code_point = expected.clone();
    by_code_point.sort();
    assert_ne!(
        by_code_point, expected,
        "the vector has to discriminate UTF-16 order from code point order"
    );
}

/// **§3.2.2 的样本:数字、字符串转义、递归排序,还有幂等。**
///
/// 输入是按 **JSON 源码**存下来的,不是解析后的值 —— 这是有意的:
/// `333333333.33333329` 要被解析成 f64 再四舍五入成 `333333333.3333333`,
/// `1E30` 变成 `1e+30`,`4.50` 变成 `4.5`,`2e-3` 变成 `0.002`。如果在向量里就
/// 提前规范化好了,这一条就只剩"读一个值再写回去"。
///
/// 字符串那一侧钉的是转义规则:控制字符用 `\u000f` 这种小写十六进制,换行用短
/// 形式,而 `/` **不转义**、非 ASCII 字符**原样输出**。一个"转义得更多"的实现
/// (把 `/` 写成 `\/`,或者把 `€` 写成 `€`)在这里就红了 —— 它的输出和
/// 所有人都不一样,但它自己看起来完全正常。
#[test]
fn jcs_reproduces_the_rfc_sample() {
    let file = vectors("rfc8785_jcs.json");
    let sample = file.get("sample").expect("sample");
    let input: Value =
        serde_json::from_str(&string(sample, "input_source")).expect("the input is JSON");

    // §3.2.3 的那一串才是规范化结果(它的键排过序)。
    assert_eq!(canonical(&input), string(sample, "canonical"));

    // 而 §3.2.2 印的那一串是"普通 JSON.stringify 会给的东西":数字已经对了,
    // 键序还是输入的。它**不是**规范化结果 —— 这条断言把两者分开,免得有人
    // 把"数字对了"当成"全都对了"。
    let stringify_output = string(sample, "stringify_output");
    assert_ne!(canonical(&input), stringify_output);
    assert_eq!(
        serde_json::from_str::<Value>(&stringify_output).unwrap(),
        input,
        "the two RFC outputs describe the same value; only the order differs"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&canonical(&input)).unwrap(),
        input,
        "canonicalization must not change the value"
    );

    // 和对自己的输出再做一次,不该有任何变化 —— 幂等。少了这一条,一个
    // "每次调用都再规范一层"的实现也能通过上面那两句。
    let twice = canonical(&serde_json::from_str::<Value>(&canonical(&input)).unwrap());
    assert_eq!(twice, canonical(&input));
}

/// **附录 B 那张表里的每一个数字,一个不差。**
///
/// 数字序列化是 JCS 里最容易被"差不多对"糊过去的部分:大多数库会把
/// `295147905179352830000` 写成 `2.9514790517935283e+20`、把 `0.000001` 写成
/// `1e-6`,看起来都合理,而 ECMAScript 的规则不是那样。
///
/// 表里那几对相邻的值是特意选的:`1e+21` 与 `999999999999999900000` 是指数
/// 记法的边界,`9.999999999999997e-7` 与 `0.000001` 是另一头,`1424953923781206.2`
/// 那条的注释写着"Round to even"。这些边界挪一格的地方都不是直觉猜得到的,
/// 只能照着表比。
#[test]
fn jcs_number_serialisation_reproduces_every_appendix_b_sample() {
    let file = vectors("rfc8785_jcs.json");
    let numbers = array(&file, "numbers");
    assert!(numbers.len() >= 20, "expected the whole appendix B table");

    for row in numbers {
        let bits = u64::from_str_radix(&string(row, "ieee754"), 16).expect("hex bits");
        let value = f64::from_bits(bits);
        let expected = string(row, "json");

        let number = serde_json::Number::from_f64(value).expect("a finite number");
        let got = canonical(&Value::Number(number));
        assert_eq!(
            got, expected,
            "0x{bits:016x} ({value}) has to canonicalize to {expected}, not {got}"
        );
    }
}

// ————————————————————————————————————————————————————————————
// 小工具
// ————————————————————————————————————————————————————————————

/// 从规范化输出里按**出现顺序**读出顶层对象的键。
///
/// 得自己扫,不能靠 `serde_json`:它的 `Map` 默认是 `BTreeMap`,读回来的那一刻
/// 顺序就没了 —— 而顺序正是这条向量要测的东西。
///
/// 只在深度 1 处、且后面紧跟冒号的字符串才算键,这样值里的冒号
/// (比如 `"Emoji: Grinning Face"`)不会被误认。
fn top_level_key_order(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut keys = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    // 反斜杠之后的那个字节是内容,不是引号。
                    if bytes[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let mut k = j + 1;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if depth == 1 && k < bytes.len() && bytes[k] == b':' {
                    // 切片连引号一起交给 serde 解转义 —— 键里的回车在输出里
                    // 是 `\r` 两个字面字符,不是一个回车。
                    keys.push(serde_json::from_str(&text[i..=j]).expect("a JSON string"));
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    keys
}

#[test]
fn the_key_order_scanner_reads_what_the_canonicalizer_wrote() {
    // 这个工具本身也是要测的:它错了的话,上面那条排序测试会以
    // "顺序不对"的样子红,而真正错的是读数的人。
    let text = r#"{"a":1,"欧":{"nested":2},"c":[{"deep":3}]}"#;
    assert_eq!(
        top_level_key_order(text),
        vec!["a".to_string(), "欧".to_string(), "c".to_string()]
    );
    assert_eq!(top_level_key_order(r#"{"\r":1,"\n":2}"#), vec!["\r", "\n"]);
    assert_eq!(top_level_key_order(r#"{"a: b":1}"#), vec!["a: b"]);
}
