//! 命令行。
//!
//! ## 两组命令,两种信任关系
//!
//! **走 socket 的**:`sign` / `list` / `status` / `unlock` / `lock`。这些是
//! **给 agent 用的** —— 它们连上守护进程,拿签名,从始至终不碰私钥字节,
//! 也不需要口令(除了 `unlock`,那是人做的)。
//!
//! **不走 socket 的**生命周期命令直接打开本地信封，仅用于当前开发流程。
//! 同 UID 的 Agent 能启动这些命令或创建 PTY；TTY 不能证明人类身份。
//! 受保护部署需要独立管理 UID、服务端互认和结构化生命周期协议，尚未交付。

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::audit::{AuditLog, Event};
use crate::client::Client;
use crate::crypto::kdf::Argon2Config;
use crate::daemon::peer::{BinaryIdentity, PeerPolicy};
use crate::daemon::state::{autolock_from_secs, thumbprint_of, DaemonState, Roots, SigningGates};
use crate::daemon::wire::{KeySummary, SignRequest};
use crate::daemon::{self, server, ServerConfig};
use crate::did::document::{self, DidDocumentSpec};
use crate::did::lifecycle;
use crate::did::did_url_path;
use crate::did::SpecFile;
use crate::error::{KeydError, Result};
use crate::keystore::layout::KeydLayout;
use crate::keystore::record::HardwareRoot;
use crate::keystore::{device, store};
use crate::tty;

/// 空闲多久自动上锁的默认值。15 分钟:够一次交互式调试,又短到不至于让
/// "昨晚开着的终端"今早还挂着一把解锁的钥匙。
const DEFAULT_IDLE_SECS: u64 = 900;

#[derive(Parser, Debug)]
#[command(
    name = "anpio-key",
    version,
    about = "Local daemon that holds did:wba Ed25519 private keys and signs RFC 9421 messages for agents",
    long_about = "An agent never holds private key bytes: the keys live only in the daemon's memory, \
                  the agent asks for signatures over a Unix socket, and the daemon rebuilds the \
                  signature base itself.",
    help_template = help_template()
)]
pub struct Cli {
    /// Override the key directory (default `~/.anpio-key`).
    #[arg(long, global = true, value_name = "DIR")]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// `--help` 的模板。
///
/// clap 4 的 help 生成器只支持整个子命令列表**一个**标题
/// (`Command::subcommand_help_heading`),没法把一个列表切成几节。所以这里
/// 不用 `{subcommands}`,按信任关系手写几节。代价是**加子命令时这里要跟着
/// 改**,`every_subcommand_is_listed_in_the_help_template` 那条测试就是盯这个的。
///
/// 分节的依据是模块头那条分界线:`serve` 是守护进程本体;`sign` / `list` /
/// `status` / `lock` / `document` 走 socket 且不要口令,agent 够得着;
/// `unlock` 也走 socket 但口令只从终端读,单独一节;其余的在人的进程里开
/// 信封；同 UID 不隔离。
///
/// 特性门控的两条只在对应构建里存在,所以按 `#[cfg]` 追加,不能写死进来 ——
/// 默认构建的 help 里出现一条敲了也没用的命令,比不列更糟。
fn help_template() -> String {
    let mut text = String::from(
        "{before-help}{about-with-newline}\n\
         {usage-heading} {usage}\n\
         \n\
         Commands:\n\
         \n\
         \x20 serve               Run the daemon: answer signing requests over a Unix socket.\n\
         \x20 serve-protected     Linux v2 transaction signer (release acceptance pending).\n\
         \x20 audit-source        Fixed-command endpoint for independent audit collection.\n\
         \x20 audit-checkpoint    Verify SQLite history against an independently retained checkpoint.\n\
         \x20 build-info          Print build mode and security-sensitive feature flags.\n\
         \x20 inspect-vault       Inspect legacy inventory; --verify tests recovery via tty.\n\
         \x20 data                Send a protected v2 request from --file through trusted config.\n\
         \x20 admin               Use the independent Linux management channel.\n\
         \x20 init-protected-state  Initialize a NEW service database explicitly.\n\
         \x20 stop                Stop the daemon `serve` left running in the background.\n\
         \n\
         For agents — over the socket, no passphrase:\n\
         \x20 sign                Sign one RFC 9421 request, print the signature headers to stdout.\n\
         \x20 list                List the keys on this machine.\n\
         \x20 status              List the unlocked keys and how long they have been unlocked.\n\
         \x20 lock                Lock.\n\
         \x20 document            Print a DID document this machine published, byte for byte.\n\
         \n\
         Sets the passphrase — do this yourself, in your own terminal:\n\
         \x20 unlock              Unlock a key.\n\
         \n\
         Identity and documents — in your own terminal:\n\
         \x20 spec                Write a document spec file (a template to edit).\n\
         \x20 keygen              Mint an identity from 24 new words: four keys, and a signed did.json.\n\
         \x20 publish             Rebuild the document from a spec, self-sign it, write did.json.\n\
         \x20 verify-doc          Check that a document really belongs to the DID it claims.\n\
         \x20 probe               Check whether this machine can keep the tool's promises.\n\
         \n\
         Keys and DID lifecycle:\n\
         \x20 add-recovery-key    Add a recovery key to a DID (pre-authorize one migration).\n\
         \x20 add-agreement-key   Add an X25519 key-agreement key (ECDH only; it cannot sign).\n\
         \x20 rotate-hot-key      Rotate the hot key used for everyday signing.\n\
         \x20 remove-key          Remove a non-binding key from the document.\n\
         \x20 migrate             Migrate to a new DID: the old document is deactivated and points at it.\n\
         \x20 deactivate          Permanently deactivate a DID, optionally naming a successor.\n\
         \n\
         Backup and restore:\n\
         \x20 import-mnemonic     Restore a binding key from 24 words, re-wrap it for this machine.\n\
         \x20 import-archive      Restore from an encrypted archive.\n",
    );

    // 特性门控的那两行单独列 —— 默认构建里它们不该出现在 help 里,一条敲了
    // 也没用的命令比不列更糟。用数组 + `#[cfg]` 而不是往 String 上 push,
    // 是为了两个特性都关掉时不出现 `unused_mut`。
    const GATED: &[&str] = &[
        #[cfg(feature = "seed-export")]
        "\x20 export-seed         Export a key's seed (the 24 words and/or an archive).\n",
        #[cfg(feature = "mcp")]
        "\x20 mcp                 Speak MCP on stdin/stdout, for an MCP client to launch.\n",
    ];
    if !GATED.is_empty() {
        text.push_str("\nOnly in builds with a feature flag:\n");
        for line in GATED {
            text.push_str(line);
        }
    }

    // 「Options:」这个标题得自己写:`{options}` 只把参数打出来,带标题的那个
    // 是 `{all-args}`,而 `{all-args}` 会连带打出 clap 自己那份**没分节**的
    // 子命令列表 —— 正是上面要避开的那一样。
    text.push_str("\nOptions:\n\n{options}{after-help}");
    text
}

/// 变体的顺序要跟 `help_template()` 里那几节对得上。
///
/// (枚举本身的文档注释**不会**进 help —— clap 只把变体上的注释当作命令
/// 说明。所以这里可以继续用中文记理由,用户看不到。)
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print build mode and enabled security-sensitive features as JSON.
    BuildInfo,
    /// Read-only legacy inventory; --verify opens every key and tests recovery via tty.
    InspectVault {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        verify: bool,
    },
    /// Run the daemon: answer signing requests over a Unix socket.
    Serve(ServeArgs),
    /// Linux v2 transaction signer; protected release acceptance remains separate.
    ServeProtected(ProtectedArgs),
    /// Explicit one-time SQLite initialization, as the dedicated service UID.
    InitProtectedState(ProtectedArgs),
    /// Authenticate to the independent Linux management socket.
    Admin(AdminArgs),
    /// Send one typed v2 data request through the authenticated configured endpoint.
    Data(DataArgs),
    /// Fixed-command read-only endpoint for an authenticated independent collector.
    AuditSource {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        instance_id: String,
    },
    /// Read-only audit evidence; retain the output in an independent trust domain.
    AuditCheckpoint {
        #[arg(long)]
        database: PathBuf,
        /// Expected service instance from trusted provisioning, not the database.
        #[arg(long)]
        instance_id: String,
        /// Previously retained checkpoint. Omit only for explicit first enrollment.
        #[arg(long, required_unless_present = "enroll", conflicts_with = "enroll")]
        previous: Option<PathBuf>,
        #[arg(long)]
        enroll: bool,
    },
    /// Stop the daemon that `serve` left running in the background.
    Stop,

    /// Sign one RFC 9421 request, print the signature headers to stdout.
    Sign(SignArgs),
    /// List the keys on this machine.
    List,
    /// List the unlocked keys and how long they have been unlocked.
    Status,
    /// Lock.
    Lock(LockArgs),
    /// Print a DID document this machine published, byte for byte.
    ///
    /// Read-only, and it needs no unlock: the document is public. It answers
    /// only for DIDs **published on this machine** — the daemon has no network,
    /// so resolving someone else's DID is the caller's job.
    Document(DocumentArgs),

    // 也走 socket,但和上面四条不同:口令只从终端读,所以这一步是人做的,
    // agent 做不了也不该做。
    /// Unlock a key (reads the passphrase from the terminal).
    Unlock(UnlockArgs),

    // 规格文件是"这份文档该有什么"的唯一来源(域名、路径、service 声明),
    // 而 `keygen` / `publish` 读它、不猜它。这条命令只是给手写减负:坐标的
    // 几条规则(域名不能是 IP、路径段必须 URL 安全)在这里当场查,而不是等到
    // 钥匙都生成出来了才在别处报错。
    /// Write a **document spec file** — start from a template, edit it from there.
    Spec(SpecArgs),
    /// Generate a new did:wba key, write the envelope into `keys/`.
    Keygen(KeygenArgs),
    /// Build the document from the spec, self-sign a proof, write did.json.
    Publish(PublishArgs),
    /// Check that a document really belongs to the DID it claims.
    VerifyDoc(VerifyDocArgs),
    // 计划里这一条是"dump 锁定区",换做法的理由见 `ops::probe` 的模块头 ——
    // 一句话:跨进程读不到(那正是 mlock 在起作用),而进程内自测会把私钥打到
    // stdout,那个口子 `export-seed` 在默认构建里是根本不存在的。
    /// Check whether this machine can keep the promises the tool makes.
    ///
    /// Prints no key material at all — safe to paste the output into an issue.
    Probe(ProbeArgs),

    /// Add a recovery key to a DID (pre-authorize one migration).
    AddRecoveryKey(AddRecoveryKeyArgs),
    /// Add an X25519 key-agreement key (for ECDH; it cannot sign).
    AddAgreementKey(AddAgreementKeyArgs),
    /// Rotate the hot key used for everyday signing.
    RotateHotKey(RotateHotKeyArgs),
    /// Remove a non-binding key from the document.
    RemoveKey(RemoveKeyArgs),
    /// Migrate to a new DID: the old document is deactivated and points at it.
    Migrate(MigrateArgs),
    /// Permanently deactivate a DID, optionally naming a successor.
    Deactivate(DeactivateArgs),

    /// Restore an identity from 24 words: four keys, re-wrapped for this machine.
    ImportMnemonic(ImportMnemonicArgs),
    /// Restore from an encrypted archive.
    ImportArchive(ImportArchiveArgs),

    // 默认构建里它不存在,不是"被拒绝",是**没有这段代码**:没有分支、没有
    // 环境变量、没有可翻的开关。简言之,一个能一键把整把身份抽干的接口,是
    // agent 被注入之后最想找的那个东西。
    //
    // 这条命令**没有** `--password`:口令只从终端读。argv 会被 `ps` 看到,
    // 环境变量会被同 uid 的进程在 `/proc/<pid>/environ` 里读到。
    /// Export a key's seed — **only in a build with the `seed-export` feature**.
    ///
    /// Not in the default build: not "refused", absent — no branch, no
    /// environment variable, no switch to flip.
    #[cfg(feature = "seed-export")]
    ExportSeed(ExportSeedArgs),
    // 这是给 **MCP 客户端的配置位**用的:配置里那一行 `command` 就指向这个
    // 子命令。它自己不开密钥库,只把几个工具转发给守护进程(见 `mcp` 模块)。
    /// Speak MCP on stdin/stdout — **only in a build with the `mcp` feature**.
    ///
    /// This is what an MCP client's config points at. It opens no keystore of
    /// its own; it forwards a handful of tools to the daemon.
    #[cfg(feature = "mcp")]
    Mcp(McpArgs),
}

#[cfg(feature = "mcp")]
#[derive(Args, Debug)]
pub struct McpArgs {
    /// Use only protected v2 tools with this administrator-owned service configuration.
    #[arg(long, conflicts_with = "socket")]
    pub config: Option<PathBuf>,
    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ProtectedArgs {
    #[arg(long, default_value = crate::security::config::DEFAULT_CONFIG)]
    pub config: PathBuf,
}

#[derive(Args, Debug)]
pub struct DataArgs {
    #[arg(long, default_value = crate::security::config::DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// A v2 DataRequest JSON file; body state must be explicit. No automatic retries.
    #[arg(long)]
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct AdminArgs {
    #[arg(long, default_value = crate::security::config::DEFAULT_CONFIG)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub operation: AdminCommand,
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Complete a prepared registration or hot-key rotation (root destroyed on return).
    CompleteSecretOperation {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        digest: String,
    },
    ListPrincipals,
    Catalog,
    /// Prepare a typed management change from a public JSON file. No passwords or seeds.
    Prepare {
        #[arg(long)]
        file: PathBuf,
    },
    PrepareRegisterPrincipal {
        #[arg(long)]
        uid: u32,
    },
    PrepareDisablePrincipal {
        #[arg(long)]
        principal_id: String,
    },
    Commit {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        digest: String,
    },
    Status,
    LockAll,
    /// Foreground macOS SE login helper. Closing it locks keys and revokes grants.
    SeSession {
        #[arg(long)]
        vault_id: String,
        #[arg(long)]
        did: String,
        #[arg(long)]
        kid: String,
    },
    Unlock {
        /// Use a native secure macOS dialog, after service authentication.
        #[arg(long)]
        native_ui: bool,
        #[arg(long)]
        vault_id: String,
        #[arg(long)]
        did: String,
        #[arg(long)]
        kid: String,
    },
}

#[derive(Args, Debug)]
pub struct ProbeArgs {
    /// Inspect the Linux deployment boundary. Remains nonzero until protected release support.
    #[arg(long)]
    pub security: bool,
    #[arg(long, default_value = crate::security::config::DEFAULT_CONFIG, requires = "security")]
    pub config: PathBuf,
    /// Also report this DID's envelope: kid, thumbprint, and whether the copy on
    /// disk reads back. All of it is public — no passphrase needed.
    #[arg(long)]
    pub did: Option<String>,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// Multi-user system service: one namespace per uid, rooted at
    /// `/var/lib/anpio-key/users/<uid>`.
    #[arg(long)]
    pub system: bool,

    /// Stay in this terminal instead of going to the background.
    ///
    /// Without it the command hands the terminal straight back and the daemon
    /// keeps running. Service managers (launchd, systemd) need this flag — they
    /// supervise a process, they do not want one that forks away from them.
    #[arg(long)]
    pub foreground: bool,

    /// Lock everything after this many idle seconds. `0` means lock
    /// **immediately**, not "never".
    #[arg(long, default_value_t = DEFAULT_IDLE_SECS, value_name = "SECS")]
    pub idle: u64,

    /// Explicitly acknowledge legacy development mode. No Agent isolation.
    #[arg(long)]
    pub development: bool,

    /// Enable arbitrary-byte signatures in development mode only.
    #[arg(long, requires = "development", conflicts_with = "system")]
    pub allow_raw_signing: bool,

    /// Enable caller-supplied challenge signatures in development mode only.
    /// The 256-byte limit is a resource limit, not purpose isolation.
    #[arg(long, requires = "development", conflicts_with = "system")]
    pub allow_challenge_signing: bool,

    /// Besides this process's own uid, which uids may connect (repeatable).
    #[arg(long = "allow-uid", value_name = "UID")]
    pub allow_uids: Vec<u32>,

    /// Allowed executable identities, `cdhash:<hex>` or `sha256:<hex>`
    /// (repeatable).
    ///
    /// Required with `--system`: a system daemon serves several uids, and the
    /// uid alone does not say which program is asking. Do not know the value
    /// yet? Start it once without this flag, then read the `--allow-binary` line
    /// the daemon writes into its log for every connection it refuses.
    #[arg(long = "allow-binary", value_name = "PIN")]
    pub allow_binaries: Vec<String>,
}

impl ServeArgs {
    fn policy(&self) -> Result<PeerPolicy> {
        let mut allowed_binaries = Vec::new();
        for pin in &self.allow_binaries {
            allowed_binaries.push(BinaryIdentity::parse(pin)?);
        }
        Ok(PeerPolicy { allowed_uids: self.allow_uids.clone(), allowed_binaries })
    }
}

#[derive(Args, Debug, Clone)]
pub struct HardwareArgs {
    /// Bind this envelope to a hardware root.
    ///
    /// `none` (the default) leaves the envelope exactly as it has always been:
    /// the passphrase plus this machine's `device.secret`. The other values add a
    /// **third** source of entropy that cannot be copied off the machine — so a
    /// stolen disk, or the whole `~/.anpio-key/` directory on another computer,
    /// stops being enough.
    ///
    /// Which names exist depends on the build and the platform:
    ///
    /// - `secure-enclave` — macOS, `--features hardware-se`
    /// - `tpm` — Linux, `--features hardware-tpm`
    /// - `software` — `--features hardware-software`; a **test stand-in**, not
    ///   hardware, and `probe` will not count it as one
    ///
    /// **There is no silent downgrade.** Asking for a root this build or this
    /// machine does not have is an error, never a fallback to `none`: an envelope
    /// that looks protected and is not is worse than one that is honestly plain.
    ///
    /// (The flag is `--hardware`, not `--root` — `--root` is already the global
    /// one that points at `~/.anpio-key`, and two different `--root`s in one
    /// command line is a trap.)
    // 字段叫 `choice` 而不是 `root`:clap 的 arg **id** 取字段名,而顶层那个
    // `--root` 是 `global = true`、会铺进每一个子命令 —— 这里再有一个 id 叫
    // `root` 的 arg,两个同名 id 会撞在一起(长名不同也没用)。
    #[arg(long = "hardware", value_name = "ROOT", default_value = "none")]
    pub choice: crate::keystore::hardware::HardwareChoice,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// The document spec file (JSON). Coordinates and service declarations come
    /// from it.
    ///
    /// Without it there is nothing to generate: a DID is "coordinates + public
    /// key", and the coordinates have to be the ones **you** wrote down, not the
    /// ones the tool picked for you. For a starter template, see
    /// `anpio-key spec --help`.
    #[arg(long, value_name = "FILE")]
    pub spec: PathBuf,

    /// A human-readable label. It goes into the AAD, so changing it means
    /// re-wrapping — it is not a comment.
    #[arg(long, default_value = "default", value_name = "LABEL")]
    pub label: String,

    #[command(flatten)]
    pub hardware: HardwareArgs,
}

#[derive(Args, Debug)]
pub struct SpecArgs {
    /// The domain you control. IP literals are refused — did:wba requires an
    /// FQDN.
    #[arg(long, value_name = "HOST")]
    pub host: String,

    /// The path before the `e1_` segment, `/`-separated (e.g. `agents/mybot`).
    #[arg(long, value_name = "A/B")]
    pub path: String,

    /// A non-default port.
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// The agent description URL the document should declare.
    #[arg(long, value_name = "URL")]
    pub agent_description_url: Option<String>,

    /// Where to write it. Without it, stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// The DID to publish.
    #[arg(long, value_name = "DID")]
    pub did: String,

    // 不给就是**沿用本地那份文档里的声明** —— 重发文档不该顺手把 service
    // 条目清掉,那是不报错的丢东西。
    //
    // 给了的话,它的坐标必须和 `--did` 说的一致(对不上直接拒,而不是挑一个
    // 信):拿一个 DID 去签另一个地方的文档,是这里最贵的一种错。
    /// The document spec file.
    ///
    /// **Without it, the declarations already in the local document are reused** —
    /// republishing should not quietly drop service entries, which is losing data
    /// without an error. If given, its coordinates must match `--did`: a mismatch
    /// is refused rather than guessed, because signing another site's document
    /// with this DID is the most expensive mistake available here.
    #[arg(long, value_name = "FILE")]
    pub spec: Option<PathBuf>,

    /// Where to write it. Without it, the local `dids/`.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyDocArgs {
    /// The DID to check.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// The document to verify. Without it, the local copy.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct UnlockArgs {
    /// The DID to unlock.
    #[arg(long, value_name = "DID")]
    pub did: String,

    // 不给就是 `--did` 名下默认那把,也就是**绑定密钥** —— 一个 DID 上后来
    // 挂的热密钥不会让老调用方不知不觉换了把钥匙签名。
    /// Unlock only this one, by fragment (`key-2`, `recovery-1`, ...).
    ///
    /// Without it, the default key under `--did` — the **binding key**. So a hot
    /// key added to a DID later never silently changes which key an existing
    /// caller signs with.
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct LockArgs {
    /// Lock only the keys under this DID. Without it, lock everything.
    #[arg(long, value_name = "DID")]
    pub did: Option<String>,

    /// Together with `--did`, narrows it to one key. Alone it means nothing
    /// (clap refuses).
    #[arg(long, value_name = "FRAGMENT", requires = "did")]
    pub kid: Option<String>,

    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DocumentArgs {
    /// The DID whose document to print.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// The DID to sign as.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// Which key to sign with, by fragment (`key-2`, `recovery-1`, ...).
    ///
    /// Without it, the default key under `--did` (the binding key).
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    /// The HTTP method.
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// The full request URI — this is RFC 9421's `@target-uri`.
    ///
    /// Only the `--raw` and `--challenge` paths do not need it, so it is
    /// required unless one of them is present.
    #[arg(long, value_name = "URL", required_unless_present_any = ["raw", "challenge"])]
    pub url: Option<String>,

    /// Headers already on the request, `name: value` (repeatable). Names are
    /// lowercased.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    /// The file holding the request body. If given, `content-digest` definitely
    /// goes into the covered set, and the daemon computes it itself — a header
    /// of the same name in the request is ignored.
    #[arg(long, value_name = "PATH")]
    pub body: Option<PathBuf>,

    /// Extra components to require covering (repeatable). **Can only add, never
    /// remove.**
    #[arg(long = "cover", value_name = "NAME")]
    pub cover: Vec<String>,

    /// The `nonce` to put in `@signature-params` — supply the **same value**
    /// that is in the request body.
    ///
    /// It has to come from here because it appears in two places at once: the
    /// body (through `content-digest`) and the signature params. The daemon
    /// only carries it; whether it means anything is the server's business.
    ///
    /// Left out, the daemon generates a random one — which is fine for
    /// single-use requests and useless for a reply the caller had to bind to a
    /// nonce it already saw.
    #[arg(long, value_name = "NONCE")]
    pub nonce: Option<String>,

    // 它和结构化那一套参数**互相排除**。不是洁癖:如果 `--raw` 能和
    // `--body`/`--cover` 一起给,调用方就会以为那些东西也进了覆盖面,而实际上
    // 原始签名的输入只有那个文件 —— 这正是"悄悄降级"的形状。要么给一套,
    // 要么给另一套,让 clap 把话说清楚。
    /// Raw-bytes signing: sign exactly the contents of this file, print base64.
    ///
    /// Needs the daemon running with `--allow-raw-signing`, and leaves an audit
    /// record every time. **Mutually exclusive** with the structured flags: if
    /// `--raw` could be combined with `--body`/`--cover`, a caller would think
    /// those went into the covered set when the raw path's only input is that
    /// file — the shape of a silent downgrade. One set or the other, so clap can
    /// say so.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["url", "headers", "body", "cover", "nonce", "challenge"]
    )]
    pub raw: Option<PathBuf>,

    // 和 `--raw` 一样，它和结构化那一套、以及和 `--raw` 本身互相排除。
    // 理由也照旧：这不是"多种输入凑在一起"的场合，而是"输入到底是哪一种"——
    // 让 clap 把话说清楚，比运行时挑一个先撞上的分支强。
    /// Challenge signing: sign exactly the contents of this file, print base64.
    ///
    /// For flows like registration, where a server issues a challenge and the
    /// caller has to prove possession of the key by signing its raw bytes. Needs
    /// the daemon running with `--development --allow-challenge-signing`.
    /// The file must be at most 256 bytes. This resource limit does not prevent
    /// document proof signing. Mutually exclusive with structured flags and raw.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["url", "headers", "body", "cover", "nonce", "raw"]
    )]
    pub challenge: Option<PathBuf>,

    /// Socket path (derived from the directory layout by default).
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AddRecoveryKeyArgs {
    /// The DID to add a recovery key to.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// A human-readable label. It goes into the AAD, so changing it means
    /// re-wrapping — it is not a comment.
    #[arg(long, default_value = "recovery", value_name = "LABEL")]
    pub label: String,

    #[command(flatten)]
    pub hardware: HardwareArgs,
}

#[derive(Args, Debug)]
pub struct AddAgreementKeyArgs {
    /// The DID to add a key-agreement key to.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// A human-readable label. It goes into the AAD, so changing it means
    /// re-wrapping — it is not a comment.
    #[arg(long, default_value = "device-agreement", value_name = "LABEL")]
    pub label: String,

    #[command(flatten)]
    pub hardware: HardwareArgs,
}

#[derive(Args, Debug)]
pub struct RotateHotKeyArgs {
    /// The DID whose hot key to rotate.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// A human-readable label for the new key.
    #[arg(long, default_value = "hot", value_name = "LABEL")]
    pub label: String,

    /// Leave the old key in the document. By default it is dropped — rotating
    /// means "stop using it".
    #[arg(long)]
    pub keep_old: bool,

    #[command(flatten)]
    pub hardware: HardwareArgs,
}

#[derive(Args, Debug)]
pub struct RemoveKeyArgs {
    /// The DID to remove a key from.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// The fragment to remove (`key-2`, `recovery-1`, ...), not the full
    /// `did#key-2`.
    ///
    /// The binding key cannot be removed — its thumbprint is the DID, so removing
    /// it would leave the document no longer binding itself.
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: String,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// The old DID. Its document is rewritten, not deleted.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// The new DID.
    #[arg(long, value_name = "DID")]
    pub to: String,

    // 默认拒,因为默认放行等于让一次打错字的 `--to` 变成一次无人察觉的
    // 冒名:验证方认"同一个 stable subject path"是同一个主体,path 一变,
    // 这条边就只能靠域名自己作证了。
    /// Allow the successor's stable subject path to differ from the old one
    /// (i.e. change domains).
    ///
    /// Refused by default, because allowing it by default would turn a typo in
    /// `--to` into an unnoticed impersonation: verifiers treat "the same stable
    /// subject path" as the same principal, and once the path changes that edge
    /// rests on the domain alone.
    #[arg(long)]
    pub allow_different_subject: bool,
}

#[derive(Args, Debug)]
pub struct DeactivateArgs {
    /// The DID to deactivate.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// Deactivate and point at this successor. Without it, this is the end of
    /// the line.
    ///
    /// This path does **not** check for cycles and does not check the stable
    /// subject path — use `migrate` for those.
    #[arg(long, value_name = "DID")]
    pub to: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportMnemonicArgs {
    /// The DID.
    ///
    /// It cannot be derived from the words: the path segments are chosen by a
    /// person, and only the public key picks the final `e1_` segment. So a person
    /// has to supply it, and a wrong one is caught **immediately** by the
    /// thumbprint — a mismatch is refused, not "cannot open".
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// The new envelope's label.
    #[arg(long, default_value = "imported", value_name = "LABEL")]
    pub label: String,

    /// Do it anyway when this machine already has the same key.
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub hardware: HardwareArgs,
}

#[derive(Args, Debug)]
pub struct ImportArchiveArgs {
    /// The archive file.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// The new envelope's label.
    #[arg(long, default_value = "imported", value_name = "LABEL")]
    pub label: String,

    /// Do it anyway when this machine already has the same key.
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub hardware: HardwareArgs,

    // 这里**没有** `--password`,而且是刻意的:归档的密码只从终端读。
    // 一个从 argv 传进来的密码会出现在 `ps` 的输出里,也会出现在 shell
    // 的历史里 —— 而它保护的是整把私钥。
}

#[cfg(feature = "seed-export")]
#[derive(Args, Debug)]
pub struct ExportSeedArgs {
    /// The DID to export from.
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// Which key. Without it, the binding key.
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    /// The directory to write the archive into.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Write even if the output file already exists.
    #[arg(long)]
    pub force: bool,

    /// Only the 24 words, no archive.
    #[arg(long, conflicts_with = "archive_only")]
    pub words_only: bool,

    /// Only the archive, do not print the 24 words.
    #[arg(long)]
    pub archive_only: bool,

    // 这里**没有** `--password`:口令只从终端读。argv 会被 `ps` 看到,
    // 环境变量会被同 uid 的进程读 `/proc/<pid>/environ`。少一个参数就是
    // 少一条泄露路径,而这个参数一旦存在,迟早会有人把它用起来。
}

/// 跑一条命令。
///
/// 先把 `Cli` 拆开:命令本身要被移出来交给各自的函数,而 `--root` 又要
/// 在后面继续用。拆开之后两者都是普通的局部变量,没有"部分移动"这回事。
pub fn run(cli: Cli) -> Result<()> {
    let Cli { root, command } = cli;
    let root = root.as_deref();
    match command {
        Command::AuditSource { database, instance_id } => {
            if root.is_some() {
                return Err(KeydError::Misuse("audit-source uses --database, not --root".into()));
            }
            let response = crate::persistence::checkpoint::source(
                &database, &instance_id, std::io::stdin().lock())?;
            println!("{}", serde_json::to_string(&response)?);
            Ok(())
        }
        Command::AuditCheckpoint {
            database,
            instance_id,
            previous,
            enroll: _,
        } => {
            if root.is_some() {
                return Err(KeydError::Misuse(
                    "audit-checkpoint uses --database, not --root".into(),
                ));
            }
            let previous = previous
                .as_deref()
                .map(crate::persistence::checkpoint::read)
                .transpose()?;
            let evidence = crate::persistence::checkpoint::inspect(
                &database,
                &instance_id,
                previous.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
            Ok(())
        }
        Command::Serve(args) => serve(root, args),
        Command::Stop => stop(root),
        Command::Keygen(args) => keygen(root, args),
        Command::BuildInfo => {
            println!("{}", serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"release":!cfg!(debug_assertions),"hardware_software":cfg!(feature="hardware-software"),"hardware_se":cfg!(feature="hardware-se"),"hardware_tpm":cfg!(feature="hardware-tpm"),"seed_export":cfg!(feature="seed-export"),"mcp":cfg!(feature="mcp"),"protected_supported":crate::security::protected_build_supported()}));
            Ok(())
        }
        Command::InspectVault { path, verify } => {
            if root.is_some() {
                return Err(KeydError::Misuse("inspect-vault uses --path, not --root".into()));
            }
            println!("{}", serde_json::to_string_pretty(&crate::security::migration::inspect(&path, verify)?)?);
            Ok(())
        }
        Command::Spec(args) => write_spec(root, args),
        Command::Publish(args) => publish(root, args),
        Command::VerifyDoc(args) => verify_doc(root, args),
        Command::List => list(root),
        Command::Status => status(root),
        Command::Probe(args) => {
            if args.security {
                if root.is_some() || args.did.is_some() {
                    return Err(KeydError::Misuse(
                        "security probe cannot use --root or --did".into(),
                    ));
                }
                crate::security::probe(&args.config)
            } else {
                crate::ops::probe::probe(root, args.did.as_deref())
            }
        }
        Command::InitProtectedState(args) => {
            if root.is_some() {
                return Err(KeydError::Misuse(
                    "state initialization cannot use --root".into(),
                ));
            }
            crate::security::require_boundary_platform()?;
            let config = crate::security::config::ServiceConfig::load(&args.config)?;
            use crate::persistence::clock::{Clock, SystemClock};
            crate::persistence::Database::initialize(&config, SystemClock.now()?)
        }
        Command::ServeProtected(args) => {
            if root.is_some() {
                return Err(KeydError::Misuse(
                    "protected endpoints cannot use --root".into(),
                ));
            }
            crate::security::require_boundary_platform()?;
            let config = crate::security::config::ServiceConfig::load(&args.config)?;
            crate::daemon::service::install_logging()?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let (stop, receiver) = tokio::sync::watch::channel(false);
                let signals = tokio::spawn(async move {
                    {
                        let mut term = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )?;
                        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
                    }
                    let _ = stop.send(true);
                    Ok::<_, std::io::Error>(())
                });
                let result = crate::security::server::serve(config, receiver).await;
                signals.abort();
                result
            })
        }
        Command::Data(args) => {
            if root.is_some() {
                return Err(KeydError::Misuse("data endpoints cannot use --root".into()));
            }
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(args.file)?
                .take((crate::security::protocol::MAX_FRAME + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > crate::security::protocol::MAX_FRAME {
                return Err(KeydError::Misuse("data input too large".into()));
            }
            let request = crate::security::json::decode(&bytes)?;
            let reply =
                crate::security::client::Client::connect(&args.config, false)?.data(request)?;
            println!("{}", serde_json::to_string(&reply)?);
            Ok(())
        }
        Command::Admin(args) => {
            if root.is_some() {
                return Err(KeydError::Misuse(
                    "admin endpoints cannot use --root".into(),
                ));
            }
            use crate::security::client::Client as AdminClient;
            let native_unlock = matches!(&args.operation, AdminCommand::Unlock { native_ui: true, .. });
            let client = AdminClient::connect(&args.config, true).map_err(|error| {
                if native_unlock { KeydError::Misuse(format!("native UI initial connection failed: {error}")) }
                else { error }
            })?;
            let reply = match args.operation {
                AdminCommand::ListPrincipals => client.principals()?,
                AdminCommand::Catalog => client.catalog()?,
                AdminCommand::Prepare { file } => {
                    use std::io::Read;
                    let limit = crate::security::protocol::MAX_FRAME / 2;
                    let mut bytes = Vec::new();
                    std::fs::File::open(file)?.take((limit + 1) as u64).read_to_end(&mut bytes)?;
                    if bytes.len() > limit {
                        return Err(KeydError::Misuse("management input too large".into()));
                    }
                    let change = crate::security::json::decode(&bytes)?;
                    client.prepare(change)?
                }
                AdminCommand::PrepareRegisterPrincipal { uid } => {
                    client.prepare(crate::persistence::Change::RegisterPrincipal { uid })?
                }
                AdminCommand::PrepareDisablePrincipal { principal_id } => {
                    client.prepare(crate::persistence::Change::DisablePrincipal { principal_id })?
                }
                AdminCommand::Commit {
                    operation_id,
                    digest,
                } => client.commit(operation_id, digest)?,
                AdminCommand::Status => client.capabilities()?,
                AdminCommand::CompleteSecretOperation { operation_id, digest } => {
                    client.capabilities()?;
                    let tty = crate::tty::open()?;
                    let secret = crate::tty::read_secret(&tty, "Management root passphrase: ")?;
                    AdminClient::connect(&args.config, true)?.complete_secret_operation(operation_id, digest, secret)?
                }
                AdminCommand::LockAll => client.lock_all()?,
                AdminCommand::SeSession { vault_id, did, kid } => {
                    if !cfg!(all(target_os = "macos", feature = "hardware-se")) {
                        return Err(KeydError::Misuse("SE login helper requires macOS and hardware-se".into()));
                    }
                    crate::security::se_session::require_local_login()?;
                    let status = client.capabilities()?;
                    if status.data.as_ref().and_then(|data| data.get("se_login_sessions")).and_then(|value| value.as_bool()) != Some(true) {
                        return Err(KeydError::Misuse("daemon does not support SE login sessions; update the reviewed daemon before prompting".into()));
                    }
                    let secret = crate::security::management_ui::se_session_secret(&args.config, &vault_id, &did, &kid)?;
                    AdminClient::connect(&args.config, true)?.se_session(vault_id, did, kid, secret)?
                }
                AdminCommand::Unlock { vault_id, did, kid, native_ui } => {
                    // Preflight before prompting; reconnect and authenticate again before sending.
                    if native_ui {
                        client.capabilities().map_err(|error| KeydError::Misuse(
                            format!("native UI initial capabilities failed: {error}")))?;
                    } else {
                        client.capabilities()?;
                    }
                    let secret = if native_ui {
                        crate::security::management_ui::unlock_secret(&args.config, &vault_id, &did, &kid)?
                    } else {
                        let terminal = tty::open()?;
                        tty::read_secret(&terminal, "Passphrase: ")?
                    };
                    let authenticated = AdminClient::connect(&args.config, true).map_err(|error| {
                        if native_ui { KeydError::Misuse(format!("native UI post-prompt connection failed: {error}")) }
                        else { error }
                    })?;
                    authenticated.unlock(vault_id, did, kid, secret).map_err(|error| {
                        if native_ui { KeydError::Misuse(format!("native UI unlock request failed: {error}")) }
                        else { error }
                    })?
                }
            };
            println!("{}", serde_json::to_string(&reply)?);
            Ok(())
        }
        Command::Unlock(args) => unlock(root, args),
        Command::Lock(args) => lock(root, args),
        Command::Sign(args) => sign(root, args),
        Command::Document(args) => document(root, args),
        Command::AddRecoveryKey(args) => crate::ops::keys::add_recovery_key(
            root,
            crate::ops::keys::AddRecoveryKey {
                did: args.did,
                label: args.label,
                hardware: args.hardware.choice,
            },
        ),
        Command::AddAgreementKey(args) => crate::ops::keys::add_agreement_key(
            root,
            crate::ops::keys::AddAgreementKey {
                did: args.did,
                label: args.label,
                hardware: args.hardware.choice,
            },
        ),
        Command::RotateHotKey(args) => crate::ops::keys::rotate_hot_key(
            root,
            crate::ops::keys::RotateHotKey {
                did: args.did,
                label: args.label,
                keep_old: args.keep_old,
                hardware: args.hardware.choice,
            },
        ),
        Command::RemoveKey(args) => crate::ops::keys::remove_key(
            root,
            crate::ops::keys::RemoveKey { did: args.did, kid: args.kid },
        ),
        Command::Migrate(args) => crate::ops::identity::migrate(
            root,
            crate::ops::identity::Migrate {
                did: args.did,
                to: args.to,
                allow_different_subject: args.allow_different_subject,
            },
        ),
        Command::Deactivate(args) => crate::ops::identity::deactivate(
            root,
            crate::ops::identity::Deactivate { did: args.did, to: args.to },
        ),
        Command::ImportMnemonic(args) => crate::ops::import::import_mnemonic(
            root,
            crate::ops::import::ImportMnemonic {
                did: args.did,
                label: args.label,
                force: args.force,
                hardware: args.hardware.choice,
            },
        ),
        Command::ImportArchive(args) => crate::ops::import::import_archive(
            root,
            crate::ops::import::ImportArchive {
                file: args.file,
                label: args.label,
                force: args.force,
                hardware: args.hardware.choice,
            },
        ),
        #[cfg(feature = "seed-export")]
        Command::ExportSeed(args) => crate::ops::export::export_seed(
            root,
            crate::ops::export::ExportSeed {
                did: args.did,
                kid: args.kid,
                out: args.out,
                force: args.force,
                form: match (args.words_only, args.archive_only) {
                    (true, _) => crate::ops::export::Form::Words,
                    (_, true) => crate::ops::export::Form::Archive,
                    _ => crate::ops::export::Form::Both,
                },
            },
        ),
        #[cfg(feature = "mcp")]
        Command::Mcp(args) => {
            if let Some(config) = args.config {
                if root.is_some() {
                    return Err(KeydError::Misuse("protected MCP cannot use --root".into()));
                }
                crate::mcp::protected::serve(config)
            } else {
                crate::mcp::serve(args.socket)
            }
        },
    }
}

// ————————————————————————————————————————————————————————————————————————
// 目录与连接
// ————————————————————————————————————————————————————————————————————————

fn layout(root: Option<&Path>) -> Result<KeydLayout> {
    let layout = match root {
        Some(root) => KeydLayout::at(root.to_path_buf()),
        None => KeydLayout::user_default()?,
    };
    crate::security::paths::deny_managed_directory(layout.root())?;
    Ok(layout)
}

fn connect(root: Option<&Path>, socket: Option<&Path>) -> Result<Client> {
    let path = match socket {
        Some(socket) => socket.to_path_buf(),
        None => layout(root)?.sock_path(),
    };
    Client::connect(&path)
}

// ————————————————————————————————————————————————————————————————————————
// serve
// ————————————————————————————————————————————————————————————————————————

/// 起守护进程。
///
/// **默认是后台的。** 它不需要终端(口令那条纪律不适用于它 —— 它从不读
/// 口令),而占着一个窗口等人来读它的输出,是让一个终端白费掉。所以除非
/// `--foreground`,这条命令把终端还回去,自己走后台。
fn serve(root: Option<&Path>, args: ServeArgs) -> Result<()> {
    let layout = service_layout(root, &args)?;
    let sock_path = socket_of(&layout, &args);

    // 多用户下的第三层:**不给 pin 就不启动。**
    //
    // 这一条放在最前面,在任何文件系统操作之前 —— `--system` 的目录要 root
    // 才建得出来,放到后面就变成"非 root 先因为权限失败",而真正的原因
    // (配置不对)反而看不见。也正因为如此,这条检查在没有 root 的机器上
    // 也是可测的。
    //
    // 单用户不打这条警告:那边的粒度**就是** uid,README 里也是这么写的
    // ("同一个 uid 下的另一个 agent"列在不挡的那一栏)。一条多数时候可以
    // 无视的警告,会教人无视下一條真正要紧的。
    if args.system && args.allow_binaries.is_empty() {
        return Err(KeydError::Misuse(format!(
            "--system serves more than one uid from a single daemon, and a uid does not say which \
             program is asking. Without --allow-binary, every process running as uid {} can connect \
             and ask for signatures.\n\
             Give it at least one pin. Do not know the value yet? Start it once with a pin that \
             matches nothing, and the daemon writes the --allow-binary line to copy into {} for \
             every connection it refuses.",
            daemon::self_uid(),
            layout.log_path().display()
        )));
    }

    if args.foreground {
        return serve_here(&layout, args, sock_path);
    }

    layout.ensure()?;
    crate::daemon::service::detach(&layout.log_path(), &sock_path, &layout.pid_path())
}

/// 单用户 → `--root` 指哪儿是哪儿;系统服务 → `/var/lib/anpio-key/users/<uid>`。
///
/// 日志和 pid 文件都跟着这个走,所以 `--system` 下的日志自然也落在
/// `/var/lib/anpio-key/users/<uid>/log/`,不用另开一套路径规则。
fn service_layout(root: Option<&Path>, args: &ServeArgs) -> Result<KeydLayout> {
    if args.system {
        KeydLayout::system(daemon::self_uid())
    } else {
        layout(root)
    }
}

fn socket_of(layout: &KeydLayout, args: &ServeArgs) -> PathBuf {
    match (&args.socket, args.system) {
        (Some(path), _) => path.clone(),
        // 系统服务的 socket 不属于任何单个 uid,所以它不能放在某个人的
        // 家目录里 —— 那个人一退出登录目录就没了,而服务还在跑。
        (None, true) => PathBuf::from("/var/run/anpio-key.sock"),
        (None, false) => layout.sock_path(),
    }
}

/// 守护进程本体 —— 前台跑、后台跑、被服务管理器拉起来,走的都是这里。
fn serve_here(layout: &KeydLayout, args: ServeArgs, sock_path: PathBuf) -> Result<()> {
    if (args.allow_raw_signing || args.allow_challenge_signing) && (!args.development || args.system) {
        return Err(KeydError::Misuse("raw/challenge signing requires --development and cannot use --system".into()));
    }
    layout.ensure()?;
    let _maintenance = crate::security::paths::legacy_lease(layout.root())?;
    crate::daemon::service::install_logging()?;
    tracing::warn!("legacy development mode: no grant enforcement or same-UID Agent isolation");
    if args.allow_raw_signing || args.allow_challenge_signing {
        tracing::warn!("arbitrary-byte signing enabled: challenge length does not prevent DID document proof signing");
    }

    let policy = args.policy()?;

    // 上次导出过就在启动时说一句。
    //
    // "家用路由器显示上次登录"那种东西,而这个比它重要:导出是把整把身份
    // 抽出来,抽出来之后**没有任何办法撤销**。守护进程是那个会被 agent
    // 够到的东西,所以它每一次被拉起来的时候都该把这件事说清楚 —— 哪怕
    // 大多数时候它只是进了日志,而人不会去看。
    //
    // 真正会被人看到的那一次在 `ops::Session::open` 里:导出这件事最后一定
    // 是被某个坐在终端前的人做掉的,而那里正是那个人眼前。
    if let Some(line) = crate::audit::log::export_tripwire(&layout.audit_dir()) {
        tracing::warn!("{line}");
    }

    let roots = if args.system {
        Roots::PerUid
    } else {
        Roots::Single(KeydLayout::at(layout.root().to_path_buf()))
    };

    let pid_path = layout.pid_path().to_path_buf();

    let state = std::sync::Arc::new(DaemonState::new(
        roots,
        policy,
        autolock_from_secs(args.idle),
        SigningGates::new(args.allow_raw_signing, args.allow_challenge_signing),
    ));
    let config = ServerConfig { sock_path: sock_path.clone(), policy: state.policy().clone() };

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let outcome = runtime.block_on(async move {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        // **先把停机信号接上,再让 socket 出现。** 这两句的先后是这儿的重点。
        //
        // [`service::detach`] 判"起来了"用的是"那个 socket 文件不是原来那个
        // 了",所以 `bind()` 一发生,父进程就打印 `listening on`、把终端还给
        // 人。而在这之后、信号处理器装上之前收到一个 SIGTERM,走的是**默认
        // 动作**:进程当场死掉 —— 不停清扫、不删 socket。症状是 `serve` 紧跟
        // 着一句 `stop`:命令报成功,磁盘上却留着一具尸体(对着刚出现的 pid
        // 文件立刻发 SIGTERM,修之前 30/30 次都留)。
        //
        // 所以 `bind` 和 pid 文件的写入都在下面。顺带把另一条也修了:起
        // runtime 或装配 state 要是失败,现在磁盘上什么都不会留下。
        //
        // [`StopSignals::install`] 必须在这一层直接调,不能只把注册塞进一个
        // `tokio::spawn` 里 —— spawn 出去的任务什么时候被轮询是调度器说了算,
        // 那样等于没有提前。
        let stop_signals = StopSignals::install()?;
        tokio::spawn(async move {
            stop_signals.wait_for_a_stop_signal().await;
            let _ = stop_tx.send(true);
        });

        // **先绑定,后写 pid 文件。** 绑定成功才是这个 socket 的守护进程;
        // 写在前面的话,一个注定要失败的第二个 `serve`(比如 socket 已经被
        // 占了)会先覆盖正在跑的那个的 pid 文件,再在退出时把它删掉 ——
        // `stop` 之后就只会对着一个活着的守护进程说 "nothing is running"。
        let listener = server::bind(&sock_path)?;
        let _pid_file = crate::daemon::service::PidFile::write(pid_path)?;

        server::serve_on(state, config, stop_rx, listener).await
    });

    // 走到这儿 socket 已经删了(server 里那段);pid 文件由 guard 在返回时
    // 删,包括出错这条路。
    outcome
}

// ————————————————————————————————————————————————————————————————————————
// stop
// ————————————————————————————————————————————————————————————————————————

/// 把 `serve` 放到后台去的那个守护进程停下来。
///
/// **不是一种 socket 消息。** 线上那几种消息类型是 README 明写的契约;
/// 为了让一条"给人用的"命令跑通去动那个契约,是拿 agent 那侧的稳定性换
/// 一点便利。
///
/// 于是走 pid 文件。而 pid 文件里那个数字**不足以**授权一次 `kill` ——
/// pid 会被内核回收,所以下面要先核对占用它的进程跑的是不是这个二进制。
fn stop(root: Option<&Path>) -> Result<()> {
    let layout = layout(root)?;
    let pid_path = layout.pid_path();

    let recorded = match std::fs::read_to_string(&pid_path) {
        Ok(text) => text,
        // 没在跑,和"已经停过了"是同一件事。`stop` 是幂等的:脚本里
        // `stop` 之后接一句 `stop` 不该报错。
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("nothing is running");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let pid: i32 = recorded.trim().parse().map_err(|_| {
        KeydError::Misuse(format!("{} does not hold a pid", pid_path.display()))
    })?;

    if !crate::daemon::process::is_alive(pid) {
        // 陈旧的 pid 文件:进程早就没了。清掉,免得下一次还要再判一遍。
        let _ = std::fs::remove_file(&pid_path);
        println!("nothing is running");
        return Ok(());
    }

    // **这里是 `stop` 唯一有分量的地方。**
    //
    // pid 会被回收:守护进程死掉之后,同一个号码可能落到任何一个新进程头
    // 上。少了这一句核对,一个陈旧的 pid 文件就能让 `stop` 去打一个无辜的
    // 进程 —— 而且打的是 SIGTERM,对方多半直接死。
    //
    // 对不上就**什么都不做**:不杀、也不删 pid 文件。文件还留着,因为它
    // 可能记着一件我们没看懂的事,而看不懂的时候动手是最坏的选择。
    let me = std::env::current_exe()?;
    if !crate::daemon::process::is_same_executable(&me, pid) {
        let other = crate::daemon::process::executable_of(pid)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "an executable I could not read".into());
        return Err(KeydError::Misuse(format!(
            "{} says pid {pid}, but that pid is running {other}, not this binary. Refusing to \
             signal it. If the daemon really is gone, remove {} yourself.",
            pid_path.display(),
            pid_path.display()
        )));
    }

    if unsafe { nix::libc::kill(pid, nix::libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // 发出去的是一个**请求**,不是保证。等它真的走,别把"我发过信号了"
    // 说成"它停了"。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::daemon::process::is_alive(pid) {
        if std::time::Instant::now() >= deadline {
            return Err(KeydError::Misuse(format!(
                "pid {pid} was asked to stop but is still there after 5s"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // 正常情况下它自己删了(guard 在返回时删)。进程被 SIGKILL 打死之类
    // 的情况下不会,所以这里补一下。
    let _ = std::fs::remove_file(&pid_path);
    println!("pid {pid} stopped");
    Ok(())
}

/// 装好了的停机信号。
///
/// 分成"装"和"等"两步,是因为**装的时刻**有约束:它必须早于 socket 文件
/// 出现,否则 `bind()` 之后、装好之前那一段里来的 SIGTERM 会把进程按默认
/// 动作打死。理由写在 [`serve_here`] 里。
struct StopSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl StopSignals {
    /// 让 SIGINT 和 SIGTERM 都走这个进程自己的停机路径。
    ///
    /// 两者都要:交互时人按的是 Ctrl-C,而 init 系统停服务时发的是 SIGTERM。
    /// 只处理一个的话,另一种情况会**直接把进程打死** —— 内存里的钥匙来不及
    /// 放掉,socket 文件也留在磁盘上,下一次启动还得先清那具尸体。
    ///
    /// **返回时处理器已经在内核里挂上了**,不是"等下挂上"。
    fn install() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};

        // 装不上的话**要失败**,不能像从前那样记一句 log 就往下走:那两个
        // 流装不上,就等于这个守护进程没有停机路径,而它会一直跑下去、谁也
        // 停不掉。现在这条路走在 socket 出现之前,所以失败什么也不留在盘上。
        let interrupt = signal(SignalKind::interrupt())
            .map_err(|error| KeydError::Misuse(format!("cannot listen for SIGINT: {error}")))?;
        let terminate = signal(SignalKind::terminate())
            .map_err(|error| KeydError::Misuse(format!("cannot listen for SIGTERM: {error}")))?;
        Ok(Self { interrupt, terminate })
    }

    async fn wait_for_a_stop_signal(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => tracing::info!("stopping: SIGINT"),
            _ = self.terminate.recv() => tracing::info!("stopping: SIGTERM"),
        }
    }
}

// ————————————————————————————————————————————————————————————————————————
// keygen
// ————————————————————————————————————————————————————————————————————————

fn keygen(root: Option<&Path>, args: KeygenArgs) -> Result<()> {
    let layout = layout(root)?;
    // 规格先读、先查,在**问口令之前** —— 人已经坐下来、敲完两遍口令之后
    // 才被告知"你这个域名不行",而这条错误本来在他敲第一个字符之前就成立。
    let spec = SpecFile::from_file(&args.spec)?.to_spec()?;

    let tty = tty::open()?;
    let passphrase =
        tty::read_secret_twice(&tty, "New passphrase for this key: ", "Repeat it: ")?;

    // 一个助记词铸出整套身份,所以词必须在**铸之前**先让人抄下来。
    //
    // 顺序反过来(先铸、再显示词)的代价是:人一句"我没抄",磁盘上就已经
    // 躺着一套**没有备份**的身份了 —— 而这套身份的四把钥匙里有一把是只能
    // 靠纸恢复的。所以这条路上唯一的落盘点排在"抄好了吗"之后。
    let seed = crate::crypto::hygiene::LockedBytes::generate()?;
    let words = crate::crypto::mnemonic::to_words(&seed)?;
    show_words(&tty, &words)?;
    if !tty::confirm(&tty, "Have you written these 24 words down?")? {
        return Err(KeydError::Misuse(
            "the words were not written down, so nothing was minted: they are the only backup \
             this identity will ever have"
                .into(),
        ));
    }

    let identity = crate::keystore::create::create_identity(
        &layout,
        &spec,
        &args.label,
        passphrase.as_bytes(),
        Argon2Config::default(),
        args.hardware.choice,
        &seed,
    )?;

    // 文档由这里当场签出来。`publish` 不再是必经之路,原因不是省一步:
    // 文档里挂什么,只有**刚刚铸出这四把的人**知道。让 `publish` 从 `keys/`
    // 反推的话,一把被 `remove-key` 摘掉的钥匙会随着下一次重发复活 ——
    // 而摘钥匙的整个意思就是让它别回来。
    let device_secret = device::load(&layout)?;
    let key = crate::keystore::unwrap::unlock(
        &identity.root,
        passphrase.as_bytes(),
        &device_secret,
    )?;
    let (did, unsigned) = document::build_unsigned_with(
        &spec,
        &key.verifying_key()?,
        identity.document_keys.clone(),
    )?;
    let signed = document::sign_document(&unsigned, &key, &identity.root.id.kid)?;
    document::verify_path_binding(&did, &signed)?;
    store::write_did_document(&layout, &did, &signed)?;

    // 落审计:这台机器上多出来一套身份。**每条信封一条**,和 `import` 那条
    // 对称 —— 只记根的话,事后问"`#device-sign` 是什么时候出现的"就答不上。
    //
    // 位置在**打印之前**:先落账,再告诉人它成了。反过来的话,一条记录写不
    // 下去的机器上,人照样会拿到一个 DID 去发布 —— 而那个 DID 在日志里不
    // 存在,正是这个文件要防的那种"说不清"。
    //
    // `hardware` 取自**刚写下去的那个信封**,不是命令行上要的那个。
    let mut audit = AuditLog::open(&layout.audit_dir())?;
    for wrapped in std::iter::once(&identity.root).chain(identity.extras.iter()) {
        audit.append(&Event::Keygen {
            did: did.clone(),
            kid: wrapped.id.kid.clone(),
            hardware: wrapped
                .hardware
                .as_ref()
                .map_or("none", HardwareRoot::kind)
                .to_string(),
        })?;
    }
    // 词出现过了 —— 记下来,但**不记词**。
    audit.append(&Event::MnemonicShown {
        did: did.clone(),
        scheme: crate::crypto::derive::DERIVATION_V2.to_string(),
    })?;
    let digest = lifecycle::document_digest(&signed)?;
    audit.append(&Event::Published { did: did.clone(), document_digest: digest })?;

    println!("{did}");
    println!();
    println!("four keys, all derived from the words you just wrote down:");
    println!("    {}  root — signs the DID document", spec.fragment);
    for extra in &identity.document_keys {
        let what = match extra.fragment.as_str() {
            crate::did::document::DEVICE_SIGN_FRAGMENT => "device signing — device assertions",
            crate::did::document::DEVICE_AGREEMENT_FRAGMENT => "key agreement — ECDH only",
            _ => "hot — everyday request signing",
        };
        println!("    {}  {what}", extra.fragment);
    }
    println!();
    println!("envelopes in {}", layout.keys_dir().display());
    println!("signed document at {}", layout.did_path(&did).display());
    println!();
    println!("it must then be served at:");
    println!("    {}", did_url_path(&did)?);
    println!();
    println!("note: this tool cannot host anything — put that file at the URL above yourself.");
    Ok(())
}

/// 在终端上把 24 个词摊开,一次,并且说明它备份的是什么、不备份什么。
///
/// 两件事必须说清楚,否则这张纸会被当成比它实际更强的保证:
///
/// 1. **没有第二次。** 没有导出路径是设计的一部分(`seed-export` 在默认
///    构建里连代码都不存在),所以这一屏就是唯一的机会。
/// 2. **纸只盖住此刻铸出来的那四把。** 以后轮换出来的热密钥是另一把随机
///    钥匙,不在这些词里 —— 那类钥匙只能靠归档带走。
fn show_words(tty: &std::fs::File, words: &str) -> Result<()> {
    use std::fmt::Write as _;

    let mut screen = zeroize::Zeroizing::new(String::new());
    let _ = writeln!(screen, "\nThese 24 words are the only backup of this identity.\n");
    for (number, word) in words.split_whitespace().enumerate() {
        let _ = writeln!(screen, "  {:>2}. {word}", number + 1);
    }
    let _ = write!(
        screen,
        "\nWrite them down by hand, now. They are shown once: this tool has no\n\
         export path, so no later command can print them again.\n\
         \n\
         The words restore the four keys minted next (root, hot, device signing,\n\
         key agreement). A key rotated later is NOT on this paper — rotation mints\n\
         a fresh random key that only ever lives on this machine.\n\n"
    );
    tty::show(tty, &screen)?;
    Ok(())
}

// ————————————————————————————————————————————————————————————————————————
// spec
// ————————————————————————————————————————————————————————————————————————

fn write_spec(_root: Option<&Path>, args: SpecArgs) -> Result<()> {
    let file = SpecFile {
        host: args.host,
        port: args.port,
        path: args.path,
        agent_description_url: args.agent_description_url,
        services: Vec::new(),
    };
    // 让 `to_spec` 查一遍再写:一份自己都算不出 DID 的规格写出去,只会把
    // 错误推迟到 `keygen`(那时候人已经坐下来准备敲口令了)。
    file.to_spec()?;

    let text = file.to_json()?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))?;
            println!("wrote {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

// ————————————————————————————————————————————————————————————————————————
// publish / verify-doc
// ————————————————————————————————————————————————————————————————————————

fn publish(root: Option<&Path>, args: PublishArgs) -> Result<()> {
    let layout = layout(root)?;
    let thumbprint = thumbprint_of(&args.did)?;
    let wrapped = store::load(&layout, &thumbprint)?;

    // 本地那份文档 —— 没有就是没发布过。它有两件事要交代:已经挂在这台
    // 机器上的热密钥和恢复密钥(重建会丢,见下),以及它自己声明过的
    // service 条目。
    let existing = match store::read_did_document(&layout, &args.did) {
        Ok(document) => Some(document),
        Err(KeydError::KeyNotFound(_)) => None,
        Err(error) => return Err(error),
    };

    // 规格:坐标从 DID 反推(文档必须挂在它自称的地方),可选项**先看
    // `--spec`,没有就沿用本地那份文档里的**。
    //
    // 后者不是省事:service 由规格决定,而重建会照规格写 —— 一份带 WNS
    // handle 绑定的文档,如果重发时不把那条声明带上,它就**静静地**没了。
    // 覆盖写不报错,只会少东西。
    let spec = match &args.spec {
        Some(path) => {
            let file = SpecFile::from_file(path)?;
            file.check_coordinates(&args.did)?;
            file.to_spec()?
        }
        None => match &existing {
            Some(document) => DidDocumentSpec::from_document(document)?,
            None => DidDocumentSpec::coordinates_from_did(&args.did)?,
        },
    };

    let tty = tty::open()?;
    let passphrase = tty::read_secret(&tty, &format!("Passphrase for {}: ", args.did))?;
    let device_secret = device::load(&layout)?;
    let key = crate::keystore::unwrap::unlock(&wrapped, passphrase.as_bytes(), &device_secret)?;

    // 文档从 DID + **刚解出来的公钥**重建,不是从磁盘读回来的那一份。
    // 重建出来的一定是规范形式,而磁盘上那一份可能是上一次留下的、或者
    // 被人改过的;要签的是"这个 DID 应有的文档",不是"别人给我们的文档"。
    //
    // 但"应有的文档"里**包含**已经挂在这台机器上的热密钥和恢复密钥 ——
    // 光按 DID 重建会得到一份只有根密钥的文档,而它盖上去之后,那两把钥匙
    // 就从文档里消失了。所以有本地文档时走 `rekey`:它在重建的同时把
    // 附加密钥和上游不认识的顶层属性一起搬回来。
    let signed = match &existing {
        Some(existing) => {
            let extras = lifecycle::extra_keys(existing, &args.did)?;
            if !extras.is_empty() {
                println!("keeping {} extra key(s) from the local document", extras.len());
            }
            let unsigned =
                lifecycle::rekey(existing, &spec, &args.did, &key.verifying_key()?, extras)?;
            let signed = document::sign_document(&unsigned, &key, &wrapped.id.kid)?;
            document::verify_path_binding(&args.did, &signed)?;
            signed
        }
        None => document::publishable(&spec, &args.did, &key)?,
    };

    let bytes = serde_json::to_vec_pretty(&signed)?;
    let path = match &args.out {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = dir.join("did.json");
            std::fs::write(&path, &bytes)?;
            path
        }
        None => {
            store::write_did_document(&layout, &args.did, &signed)?;
            // 文档落了本地那一份,才算一次本机状态变更 —— 所以记在**写之后**,
            // 而且记的是写下去的那串字节的摘要(规范化 JSON 的 SHA-256,和
            // 取件那条 `DOCUMENT_READ` 同一个函数,两者事后能对上)。
            // `--out` 那一支不记,理由见 `Event::Published`。
            let digest = lifecycle::document_digest(&signed)?;
            let mut audit = AuditLog::open(&layout.audit_dir())?;
            audit.append(&Event::Published {
                did: args.did.clone(),
                document_digest: digest,
            })?;
            layout.did_path(&args.did)
        }
    };

    let url = did_url_path(&args.did)?;
    println!("wrote {}", path.display());
    println!();
    println!("it must be served at:");
    println!("    {url}");
    println!();
    println!("note: this tool cannot host anything — whoever controls {} has to put", host_of(&url));
    println!("      that file there.");
    Ok(())
}

fn verify_doc(root: Option<&Path>, args: VerifyDocArgs) -> Result<()> {
    let bytes = match &args.file {
        Some(path) => std::fs::read(path)?,
        None => {
            let layout = layout(root)?;
            std::fs::read(layout.did_path(&args.did)).map_err(|error| {
                KeydError::Protocol(format!(
                    "no local document for {} ({error}); pass --file to verify one you downloaded",
                    args.did
                ))
            })?
        }
    };

    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| KeydError::Protocol(format!("the document is not JSON: {error}")))?;

    document::verify_path_binding(&args.did, &document)?;

    println!("{} is valid", args.did);
    println!("    proof:        verified");
    println!("    path binding: the root key's thumbprint matches the e1_ segment of the DID");

    if args.file.is_none() {
        // 本地这一份验过,不代表线上那一份还在。托管方随时能把它换成 404
        // 或一份 deactivated —— 那不在本工具的边界里,但人得被告知去查。
        println!();
        println!("this is the LOCAL copy; check the live one with:");
        println!(
            "    curl -sS {} | anpio-key verify-doc --did {} --file /dev/stdin",
            did_url_path(&args.did)?,
            args.did
        );
    }
    Ok(())
}

/// 从解析出来的 URL 里取主机(含端口)—— 只为了把"谁该去放这个文件"说清楚。
fn host_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme.split('/').next().unwrap_or(after_scheme).to_string()
}

// ————————————————————————————————————————————————————————————————————————
// list / status / unlock / lock / sign
// ————————————————————————————————————————————————————————————————————————

fn list(root: Option<&Path>) -> Result<()> {
    let mut client = connect(root, None)?;
    let keys = client.list_keys()?;

    if keys.is_empty() {
        println!("no keys on this machine");
        return Ok(());
    }
    for KeySummary { did, kid, algorithm } in keys {
        println!("{did}\t{}\t{kid}", algorithm_label(algorithm));
    }
    Ok(())
}

fn algorithm_label(algorithm: crate::keystore::KeyAlgorithm) -> &'static str {
    match algorithm {
        crate::keystore::KeyAlgorithm::Ed25519 => "ed25519",
        crate::keystore::KeyAlgorithm::P256 => "p256",
        crate::keystore::KeyAlgorithm::X25519 => "x25519",
    }
}

/// 只打印**已经解锁的**。没解锁的钥匙不在这个列表里 —— 守护进程不知道它
/// 现在长什么样,它只知道磁盘上有个信封。
fn status(root: Option<&Path>) -> Result<()> {
    let mut client = connect(root, None)?;
    let unlocked = client.status()?;

    if unlocked.is_empty() {
        println!("nothing is unlocked");
        return Ok(());
    }
    for key in unlocked {
        println!("{}\tunlocked {}s ago", key.did, key.unlocked_secs);
    }
    Ok(())
}

fn unlock(root: Option<&Path>, args: UnlockArgs) -> Result<()> {
    // 口令从终端读。**不走 argv** —— argv 对同机器上任何用户可见。
    let tty = tty::open()?;
    let passphrase = tty::read_secret(&tty, &format!("Passphrase for {}: ", args.did))?;

    let mut client = connect(root, args.socket.as_deref())?;
    client.unlock(&args.did, args.kid.as_deref(), &passphrase)?;
    println!("unlocked {}", args.did);
    Ok(())
}

fn lock(root: Option<&Path>, args: LockArgs) -> Result<()> {
    let mut client = connect(root, args.socket.as_deref())?;
    client.lock(args.did.as_deref(), args.kid.as_deref())?;
    match &args.did {
        Some(did) => println!("locked {did}"),
        None => println!("locked everything"),
    }
    Ok(())
}

/// 读一个"命令行指过来的文件",读不到时说清楚是**哪个**文件。
///
/// `std::fs::read(path)?` 展开成的是 `io: No such file or directory (os
/// error 2)`,一个字都没提那个路径。而 `--body` 最容易踩的就是这个坑:
/// 习惯上 `--header` 收的是字面量,于是很自然地把请求体也照着字面量写,
/// `--body '{"a":1}'` —— 得到的是一句没有任何上下文的话。说了文件名,
/// 人一眼就知道它要的是文件。
fn read_flag_file(path: &Path, flag: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| {
        KeydError::Protocol(format!(
            "cannot read {flag} {}: {error} (this flag takes a file, not the text itself)",
            path.display()
        ))
    })
}

fn sign(root: Option<&Path>, args: SignArgs) -> Result<()> {
    let mut client = connect(root, args.socket.as_deref())?;

    if let Some(path) = &args.raw {
        let payload = read_flag_file(path, "--raw")?;
        let signature = client.sign_raw(&args.did, args.kid.as_deref(), payload)?;
        println!("{}", base64(&signature));
        return Ok(());
    }

    if let Some(path) = &args.challenge {
        let challenge = read_flag_file(path, "--challenge")?;
        let signature = client.sign_challenge(&args.did, args.kid.as_deref(), challenge)?;
        println!("{}", base64(&signature));
        return Ok(());
    }

    let body = match &args.body {
        Some(path) => Some(read_flag_file(path, "--body")?),
        None => None,
    };

    // clap 保证了走到这里 `url` 一定在:要么给了 `--url`,要么给了 `--raw`
    // 或 `--challenge` 而这个分支处理不了 —— 所以这里的 `ok_or` 不是"用户传错
    // 了",是"我们自己把几条路的分支写漏了",报出来比 unwrap 好。
    let target_uri = args.url.clone().ok_or_else(|| {
        KeydError::Protocol("no --url was given, so there is nothing to sign".into())
    })?;

    let signed = client.sign(SignRequest::Structured {
        did: args.did.clone(),
        kid: args.kid.clone(),
        method: args.method.clone(),
        target_uri,
        headers: parse_headers(&args.headers)?,
        body,
        covered: args.cover.clone(),
        nonce: args.nonce.clone(),
    })?;

    // **原样搬运。** 这份字节要挂到真实请求上去,改动其中任何一个字符
    // 签名就验不过 —— 所以这里不解析、不重排、不补引号。
    std::io::stdout().write_all(&signed)?;
    Ok(())
}

/// 打印一份本机发布过的 DID 文档。
///
/// **原样搬运,不解析、不重排、不补缩进。** 这是一件签好名的成品,它的字节
/// 就是被签的那些字节 —— 内联进别的东西里、或者和服务端手里那份比,靠的都是
/// "逐字节一样"。所以走 socket 拿的是文件原文,而不是守护进程重新序列化一遍
/// 的结果(`crate::keystore::store::read_did_document_bytes`)。
fn document(root: Option<&Path>, args: DocumentArgs) -> Result<()> {
    let mut client = connect(root, args.socket.as_deref())?;
    let bytes = client.document(&args.did)?;
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

/// `name: value` → 头表。名字转小写。
///
/// 转小写不是洁癖:HTTP 头名不区分大小写,而 `BTreeMap` 区分 —— 不转的话
/// `Content-Type` 和 `content-type` 会成为两条记录,一条被签、另一条被
/// 忽略,而调用方以为自己两条都给了。
fn parse_headers(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    for entry in raw {
        let (name, value) = entry
            .split_once(':')
            .ok_or_else(|| KeydError::Protocol(format!("{entry:?} is not `name: value`")))?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(KeydError::Protocol(format!("{entry:?} has an empty header name")));
        }
        if headers.insert(name.clone(), value.trim().to_string()).is_some() {
            return Err(KeydError::Protocol(format!(
                "the header {name} was given twice; the second one would silently win"
            )));
        }
    }
    Ok(headers)
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::Parser;
    use clap::error::ErrorKind;

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        let mut full = vec!["anpio-key"];
        full.extend_from_slice(argv);
        Cli::try_parse_from(full)
    }

    #[test]
    fn protected_cli_has_no_socket_or_secret_override() {
        assert!(parse(&["admin", "--socket", "/tmp/fake", "status"]).is_err());
        assert!(parse(&["admin", "unlock", "--passphrase", "secret"]).is_err());
        assert!(parse(&["probe", "--config", "/tmp/fake"]).is_err());
        assert!(parse(&["probe", "--security"]).is_ok());
        assert!(parse(&["serve-protected"]).is_ok());
    }

    #[test]
    fn arbitrary_byte_signing_requires_explicit_development_and_rejects_system() {
        for flag in ["--allow-raw-signing", "--allow-challenge-signing"] {
            assert!(parse(&["serve", flag]).is_err());
            assert!(parse(&["serve", "--development", flag]).is_ok());
            assert!(parse(&["serve", "--development", "--system", flag]).is_err());
        }
    }

    /// **每一条子命令都得在 `--help` 里出现。**
    ///
    /// `help_template()` 里那份分节清单是手写的(理由见那个函数的文档注释),
    /// 手写的东西会漂:加了子命令忘了改模板,help 里就少一条 —— 而 help 是
    /// 多数人唯一会读的那份文档。这条测试就是模板注释里承诺的那一条。
    ///
    /// 按**空白分隔的整词**匹配,不是子串:`lock` 是 `unlock` 的一个子串,
    /// 子串匹配下真把 `lock` 那行删了也测不出来。
    #[test]
    fn every_subcommand_is_listed_in_the_help_template() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        let listed: Vec<&str> = help.split_whitespace().collect();

        let names: Vec<&str> = command
            .get_subcommands()
            .map(|sub| sub.get_name())
            // clap 自己补的那条 `help` 不算 —— 清单里列它没有信息量。
            .filter(|name| *name != "help")
            .collect();

        // 免得这条测试空转:`get_subcommands()` 要是返回空,下面那个 `missing`
        // 永远为空,而空列表同样是"通过"。
        assert!(
            names.len() > 10,
            "只拿到 {} 条子命令,这个数不对,先怀疑测试本身: {names:?}",
            names.len()
        );

        let missing: Vec<&str> = names
            .into_iter()
            .filter(|name| !listed.contains(name))
            .collect();

        assert!(
            missing.is_empty(),
            "这些子命令在 `--help` 里找不到,`help_template()` 的分节清单要跟着改: {missing:?}"
        );
    }

    /// **导出这条命令在默认构建里不存在 —— 不是被拒,是没有。**
    ///
    /// 计划 §六·七 的第三道收紧就是这个意思:一个运行期开关可以被补丁、
    /// 被漏掉的分支、被调试器翻过去;一个编译期不存在的子命令没有可翻的
    /// 东西。默认二进制里不但没有这条路径,连这个字符串都没有。
    #[cfg(not(feature = "seed-export"))]
    #[test]
    fn the_default_build_has_no_export_subcommand_at_all() {
        let error = parse(&["export-seed", "--did", "did:wba:example.com:u:a:e1_x"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{error}");
    }

    /// 带上 `seed-export` 构建出来的二进制里,这条命令也没有 `--password`。
    ///
    /// 这一条测的**不是**"我们记得检查了密码在不在 argv 里",而是"这个参数
    /// 根本不存在":少了参数就少了一条泄露路径,而 argv 对同机器上任何用户
    /// 都是可读的(`ps`)。
    #[cfg(feature = "seed-export")]
    #[test]
    fn the_export_command_has_no_password_flag_even_when_it_exists() {
        let error = parse(&[
            "export-seed",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--password",
            "hunter2",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
    }

    /// 两条导入路都进默认构建,而且**都没有** `--password` —— 同一条理由:
    /// 归档的密码只从终端读。
    #[test]
    fn neither_import_command_takes_a_password_on_the_command_line() {
        let mnemonic = parse(&[
            "import-mnemonic",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--password",
            "hunter2",
        ])
        .unwrap_err();
        assert_eq!(mnemonic.kind(), ErrorKind::UnknownArgument, "{mnemonic}");

        let archive = parse(&["import-archive", "--file", "/tmp/a.json", "--password", "hunter2"])
            .unwrap_err();
        assert_eq!(archive.kind(), ErrorKind::UnknownArgument, "{archive}");
    }

    /// 导入是 v1 必做的一部分 —— 一个打不开的备份不算备份。这条钉住的是
    /// "它在默认构建里",而不是"它被实现了"(那由别的测试保证)。
    #[test]
    fn both_import_commands_are_in_the_default_build() {
        assert!(parse(&[
            "import-mnemonic",
            "--did",
            "did:wba:example.com:u:a:e1_x",
        ])
        .is_ok());
        assert!(parse(&["import-archive", "--file", "/tmp/a.json"]).is_ok());
    }

    /// `--words-only` 和 `--archive-only` 一起给是自相矛盾的要求,clap 就该
    /// 在启动前拒掉 —— 不给"两个都要"和"两个都不要"这两种读法留空间。
    #[cfg(feature = "seed-export")]
    #[test]
    fn asking_for_words_only_and_archive_only_at_once_is_refused() {
        let error = parse(&[
            "export-seed",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--words-only",
            "--archive-only",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{error}");
    }

    /// 一份规格文件 —— `keygen` / `publish` 读的就是它,走的是同一条
    /// `to_spec`。所以下面几条"坐标不合法"的验收,验的正是人敲命令时
    /// 会撞上的那条路(而它在**问口令之前**就会炸:`keygen` 先读文件)。
    fn spec(host: &str, path: &str) -> Result<DidDocumentSpec> {
        SpecFile {
            host: host.to_string(),
            port: None,
            path: path.to_string(),
            agent_description_url: None,
            services: Vec::new(),
        }
        .to_spec()
    }

    #[test]
    fn a_path_is_split_on_slashes_and_tolerates_surrounding_ones() {
        let spec = spec("example.com", "/agents/mybot/").unwrap();
        assert_eq!(spec.path_segments, ["agents", "mybot"]);
    }

    /// 空段要拒 —— `a//b` 拼出来的 DID 和它看起来的样子不是一回事。
    #[test]
    fn an_empty_path_segment_is_refused() {
        let error = spec("example.com", "a//b").unwrap_err();
        assert!(error.to_string().contains("empty path segment"), "{error}");
    }

    /// **apex 不是合法的 did:wba DID。**
    ///
    /// `did:wba:example.com:e1_...` 看起来很像回事,但上游要求至少有一段
    /// 路径,所以它建不出文档。这条曾经是在人敲完两遍口令之后才炸的 ——
    /// 现在它在问口令之前就炸,而且说的话是"为什么"。
    #[test]
    fn a_did_with_no_path_segment_is_refused_before_the_prompt() {
        for path in ["", "/", "///"] {
            let error = spec("example.com", path).unwrap_err();
            let text = error.to_string();
            assert!(text.contains("no segments"), "{path:?}: {text}");
        }
    }

    /// IP 字面量要在问口令之前拒 —— did:wba 是按域名命名的。
    #[test]
    fn an_ip_literal_host_is_refused_before_the_prompt() {
        for host in ["127.0.0.1", "192.0.2.10", "::1"] {
            let error = spec(host, "agents/bot").unwrap_err();
            let text = error.to_string();
            assert!(text.contains("IP"), "{host}: {text}");
        }
    }

    #[test]
    fn an_empty_host_is_refused_before_the_prompt() {
        let error = spec("   ", "agents/bot").unwrap_err();
        assert!(error.to_string().contains("domain"), "{error}");
    }

    /// 主机两头的空白要削掉 —— 粘贴域名的时候很容易带进来。
    #[test]
    fn a_host_is_trimmed() {
        let spec = spec("  example.com  ", " agents/bot ").unwrap();
        assert_eq!(spec.host, "example.com");
        assert_eq!(spec.path_segments, ["agents", "bot"]);
    }

    #[test]
    fn header_names_are_lowercased_so_one_header_is_one_entry() {
        let headers = parse_headers(&["Content-Type: application/json".into()]).unwrap();
        assert_eq!(headers["content-type"], "application/json");
    }

    /// 大小写不同的同一个头必须被认出是重复,而不是悄悄变成两条。
    #[test]
    fn a_header_given_twice_is_refused() {
        let error = parse_headers(&[
            "Content-Type: application/json".into(),
            "content-type: text/plain".into(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn a_header_without_a_colon_is_refused() {
        let error = parse_headers(&["garbage".into()]).unwrap_err();
        assert!(error.to_string().contains("name: value"), "{error}");
    }

    /// 值里的冒号不能当分隔符 —— `Authorization: Bearer a:b` 是常见的。
    #[test]
    fn only_the_first_colon_splits_a_header() {
        let headers = parse_headers(&["authorization: Bearer a:b:c".into()]).unwrap();
        assert_eq!(headers["authorization"], "Bearer a:b:c");
    }

    #[test]
    fn a_binary_pin_that_is_not_a_pin_is_refused() {
        let error = ServeArgs {
            socket: None,
            system: false,
            foreground: false,
            idle: DEFAULT_IDLE_SECS,
            development: false,
            allow_raw_signing: false,
            allow_challenge_signing: false,
            allow_uids: vec![],
            allow_binaries: vec!["not-a-pin".into()],
        }
        .policy()
        .unwrap_err();
        assert!(error.to_string().contains("cdhash"), "{error}");
    }

    #[test]
    fn the_host_comes_out_of_a_resolution_url() {
        assert_eq!(host_of("https://example.com:3000/user/alice/did.json"), "example.com:3000");
        assert_eq!(host_of("https://example.com/.well-known/did.json"), "example.com");
    }
}
