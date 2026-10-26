//! 纯软件的假后端 —— **只为了让 v2 格式在没有硬件的机器上能被测**。
//!
//! 它把 HS 写进一个 0600 的文件,路径记在信封里。它和真硬件的差别正是这一整
//! 块要拿到的东西:**把 `~/.anpio-key/` 拷到另一台机器,那个路径跟不过去**,
//! 于是信封打不开。真硬件把这件事做得更强(HS 那 32 字节根本出不来),但
//! "打不开"这个**形状**是一样的,所以版本分派、AAD 绑定、降级拒绝这些东西
//! 可以在这里被真的测出来,而不是只能靠读代码。
//!
//! # 它自己承认自己不是硬件
//!
//! [`HardwareBackend::is_hardware`] 返回 `false`,而 `probe` 只把真后端算进
//! 体检。所以这个后端**不可能**制造出"看起来在保护、其实没有"的中间态:
//! 谁都能看出它是个替身,而且没有任何一层会把它当成硬件根报上去。
//!
//! 它只在 `hardware-software` 构建里存在,默认构建里连代码都没有。

use std::path::{Path, PathBuf};

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::layout::{write_atomic, SECRET_FILE_MODE};
use crate::keystore::record::HardwareRoot;

use super::{software_root_dir, HardwareBackend, SealedHardware};

pub static SOFTWARE: SoftwareRoot = SoftwareRoot;

pub struct SoftwareRoot;

/// 每把钥匙一个文件,名字就是指纹 —— 所以同一个 thumbprint 不会和别的信封
/// 共用一份 HS。
const HS_FILE: &str = "hs";

impl HardwareBackend for SoftwareRoot {
    fn describe(&self) -> &'static str {
        "software stand-in (NOT hardware)"
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn seal(&self, tag_hint: &str) -> Result<SealedHardware> {
        let dir = holder_dir(tag_hint)?;
        let path = dir.join(HS_FILE);

        // 已经是别人的了就拒绝,不覆盖 —— 覆盖会把上一个信封的第三路熵
        // 悄悄换掉,症状是"那把钥匙突然打不开了",而不是任何一个报错。
        if path.exists() {
            return Err(KeydError::KeyExists(format!(
                "the software stand-in root already holds a secret at {}",
                path.display()
            )));
        }

        // 替身这一侧的第三路熵是**直接生成**的 —— 这是它和真硬件的又一处差别:
        // 真硬件那两侧的 HS 要么由 TPM 造(密封对象的内容在芯片里生成),
        // 要么由 ECDH 推导(SE),都不是"外面给一个随机数存进去"。
        let hs = LockedBytes::generate()?;
        hs.expose(|bytes| write_atomic(&path, bytes, SECRET_FILE_MODE))?;

        let tag = dir.to_string_lossy().into_owned();
        Ok(SealedHardware {
            root: HardwareRoot::Software { tag },
            ciphertext: Vec::new(),
            hs,
        })
    }

    fn open(&self, root: &HardwareRoot, _ciphertext: &[u8]) -> Result<LockedBytes> {
        let HardwareRoot::Software { tag } = root else {
            return Err(KeydError::Protocol(
                "the software stand-in root was handed a record for a different kind of root".into(),
            ));
        };
        let path = Path::new(tag).join(HS_FILE);

        // `read_secret_file` 会拒绝任何不是 0600 的文件,所以这里的路径虽然
        // 是记录给的、又由 AAD 保护,真正把关的还是"只有属主读得到的文件"
        // 这一条 —— 读它不需要任何调用方本来就有的权限之外的权限。
        let raw = match crate::keystore::layout::read_secret_file(&path) {
            Ok(raw) => raw,
            Err(_) => {
                return Err(KeydError::HardwareMissing(format!(
                    "this envelope is bound to the software stand-in root, and {} is not there \
                     (or is not a 0600 file) — the envelope was probably made against a root \
                     directory that this machine does not have",
                    path.display()
                )))
            }
        };

        let mut buf = [0u8; 32];
        if raw.len() != 32 {
            return Err(KeydError::Protocol(format!(
                "the software stand-in root at {} holds {} bytes, expected 32",
                path.display(),
                raw.len()
            )));
        }
        buf.copy_from_slice(&raw);
        LockedBytes::new(&mut buf)
    }
}

/// `<root>/<tag_hint>`,而且 `tag_hint` 不许带路径分隔符。
///
/// 它今天来自我们自己的指纹,但这是**外部输入的形状**,而拼路径就是那类
/// "看起来没问题、直到有人把一个 `../` 塞进来"的地方 —— 挡在这里比挡在
/// 每个调用方便宜。
fn holder_dir(tag_hint: &str) -> Result<PathBuf> {
    let safe = !tag_hint.is_empty()
        && tag_hint.len() <= 128
        && tag_hint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !safe {
        return Err(KeydError::Protocol(format!(
            "{tag_hint:?} is not usable as a software stand-in root name"
        )));
    }
    Ok(software_root_dir()?.join(tag_hint))
}
