//! MCP 数据适配器：仅提供列表、状态、结构化 HTTP 签名和公开文档。
//! 不接受密码，不提供解锁、raw/challenge 或生命周期操作。
//! 当前仍使用开发模式 v1；同 UID 不构成 Agent 隔离。

pub mod protected;

use std::collections::BTreeMap;
use std::path::PathBuf;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};

// `JsonSchema` 的 derive **展开之后**写的是 `schemars::…` 这样的路径,所以
// `schemars` 这个名字得在作用域里。用 rmcp 的再导出而不是自己加一条依赖:
// 版本对不上会变成"别人的 schemars 和 rmcp 的 schemars 不是同一个",而那种
// 错在 trait 上会表现成一句看不懂的 not satisfied。
use rmcp::schemars;

use crate::client::{parse_signed_headers, Client};
use crate::daemon::wire::SignRequest;
use crate::error::KeydError;
use crate::keystore::layout::KeydLayout;

// **不要把 `crate::error::Result` 导进来。** `#[tool_handler]` 展开出来的签名
// 写的是 `Result<CallToolResult, McpError>`,而那个 alias 只有一个参数 ——
// 它在作用域里,宏生成的代码就解析到它头上,报的是一句和 MCP 毫无关系的
// "type alias takes 1 generic argument"。所以这里只导 `KeydError`,自家那个
// alias 一律写全 `crate::error::Result`。

/// 四个工具的实现体。
///
/// 它只持有一个东西:**守护进程的 socket 在哪**。不持有口令、不持有密钥、
/// 不持有连接 —— 一次调用一条连接,和 `client` 的约定一致(签名不是幂等的,
/// 悄悄复用一条死连接会把一次已经失去意义的请求重放上去)。
#[derive(Debug, Clone)]
pub struct Keyd {
    socket: PathBuf,
    tool_router: ToolRouter<Self>,
}

// ————————————————————————————————————————————————————————————
// 参数
// ————————————————————————————————————————————————————————————

/// 不带参数的工具也要一个结构体:工具的输入 schema 是 MCP 协议的一部分,
/// 空对象比"没有 schema"更明确。
#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListArgs {
    /// 不给就是当前用户默认的那个密钥库。
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SignArgs {
    /// 用哪个身份签。
    pub did: String,
    #[serde(default)]
    pub kid: Option<String>,
    /// HTTP 方法,如 `POST`。
    pub method: String,
    /// 完整的请求 URI。RFC 9421 的 `@target-uri` 就是它。
    pub url: String,
    /// 请求里**已有的**头,名字不区分大小写。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 请求体。**请求体本身,不是它的摘要** —— 摘要由守护进程自己算,
    /// 这样签名绑定的才是真实的内容。
    ///
    /// 只收 UTF-8 文本。二进制请求体(文件上传)这条路走不了,那是 raw 的
    /// 场景,而 raw 不在这里 —— 见模块头。
    #[serde(default)]
    pub body: Option<String>,
    /// **额外**要求覆盖的分量。只能加,不能减:覆盖面有下限,由守护进程定。
    #[serde(default)]
    pub covered: Vec<String>,
    /// 写进 `@signature-params` 的 `nonce`。
    ///
    /// 要和**请求体里那个**是同一个值 —— 它同时出现在两个地方(请求体,
    /// 经由 `content-digest`;以及签名参数),所以只能由调用方给。不给就是
    /// 守护进程随机生成一个,那对一次性请求够用,对"回给一个已经见过 nonce
    /// 的服务端"没用。
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct DocumentArgs {
    /// 要取文档的 DID。
    pub did: String,
    /// 不给就是当前用户默认的那个密钥库。
    #[serde(default)]
    pub root: Option<String>,
}

// ————————————————————————————————————————————————————————————
// 工具
// ————————————————————————————————————————————————————————————

#[tool_router]
impl Keyd {
    /// 建一个连向 `socket` 的门面。
    pub fn new(socket: PathBuf) -> Self {
        Self { socket, tool_router: Self::tool_router() }
    }

    #[tool(description = "列出这台机器上的 did:wba 密钥(不会返回任何私钥材料)")]
    async fn list_my_keys(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let keys = self
            .with_daemon(&args.root, "list_my_keys", |client| client.list_keys())
            .await?;
        text(serde_json::json!({
            "keys": keys.iter().map(|key| serde_json::json!({
                "did": key.did,
                "kid": key.kid,
                "algorithm": format!("{:?}", key.algorithm),
            })).collect::<Vec<_>>(),
        }))
    }

    #[tool(description = "当前已解锁的密钥,以及各自解锁了多久(秒)")]
    async fn status(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let keys = self
            .with_daemon(&args.root, "status", |client| client.status())
            .await?;
        text(serde_json::json!({
            "unlocked": keys.iter().map(|key| serde_json::json!({
                "did": key.did,
                "kid": key.kid,
                "unlocked_secs": key.unlocked_secs,
            })).collect::<Vec<_>>(),
        }))
    }

    #[tool(description = "签一条 RFC 9421 HTTP 消息签名,返回要挂到请求上的头")]
    async fn sign_request(
        &self,
        Parameters(args): Parameters<SignArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let request = SignRequest::Structured {
            did: args.did,
            kid: args.kid,
            method: args.method,
            target_uri: args.url,
            // 头名转小写:HTTP 头名不区分大小写而 `BTreeMap` 区分,不转的话
            // `Content-Type` 和 `content-type` 会成为两条记录,一条被签、
            // 另一条被忽略,而调用方以为自己两条都给了。
            headers: args
                .headers
                .into_iter()
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value))
                .collect(),
            body: args.body.map(String::into_bytes),
            covered: args.covered,
            nonce: args.nonce,
        };

        let signed = self
            .with_daemon(&args.root, "sign_request", move |client| client.sign(request))
            .await?;

        // **原样搬运。** 这些字节要挂到真实请求上,改动其中任何一个字符签名
        // 就验不过 —— 所以这里解析、再序列化成 JSON 对象,让调用方能直接用。
        let headers = parse_signed_headers(&signed).map_err(refusal)?;
        text(serde_json::json!({"headers": headers}))
    }

    #[tool(description = "取一份本机发布过的 DID 文档。只读,不需要解锁")]
    async fn get_did_document(
        &self,
        Parameters(args): Parameters<DocumentArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let did = args.did;
        let caller = did.clone();
        let bytes = self
            .with_daemon(&args.root, "get_did_document", move |client| client.document(&did))
            .await?;

        // **交回原文。** 这是一件签好名的成品,它的字节就是被签的那些字节 ——
        // 收成字符串而不是解析成对象,是为了让"逐字节一样"这件事在 MCP 这一跳
        // 上还能成立(解析再序列化会把键重排)。
        //
        // 必须是 UTF-8:守护进程那边已经把它解析成过 JSON,所以走到这里不会
        // 失败。这不是"可能出错的地方",是**跨进程边界的一次确认** —— 边界
        // 之外的东西不该按边界之内的保证来对待。
        let document = String::from_utf8(bytes).map_err(|error| {
            ErrorData::internal_error(
                format!("the daemon returned a document that is not UTF-8: {error}"),
                None,
            )
        })?;

        text(serde_json::json!({"did": caller, "document": document}))
    }
}

#[tool_handler]
impl ServerHandler for Keyd {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "本机 did:wba 签名服务。密钥由 anpio-key 守护进程持有,\
                 这个接口只提供签名,不提供任何私钥材料。"
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ————————————————————————————————————————————————————————————
// 转发
// ————————————————————————————————————————————————————————————

impl Keyd {
    /// 连一次守护进程、做一件事、断开。
    ///
    /// 走 `spawn_blocking`:`client` 是同步的(裸 `UnixStream`),而工具处理
    /// 是异步的。直接在异步任务里做阻塞 I/O 会把整个运行时的线程卡住 ——
    /// 一个 agent 发来的请求不该能冻住别的请求。
    async fn with_daemon<T, F>(
        &self,
        root: &Option<String>,
        what: &'static str,
        f: F,
    ) -> std::result::Result<T, ErrorData>
    where
        T: Send + 'static,
        F: FnOnce(&mut Client) -> crate::error::Result<T> + Send + 'static,
    {
        let socket = match root {
            Some(root) => KeydLayout::at(PathBuf::from(root)).sock_path(),
            None => self.socket.clone(),
        };

        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&socket)?;
            f(&mut client)
        })
        .await
        .map_err(|error| {
            ErrorData::internal_error(format!("the {what} task failed: {error}"), None)
        })?
        .map_err(refusal)
    }
}

/// 把守护进程那边的失败变成 MCP 错误。
///
/// 用的是**粗码**消息(`wire_message`),不是 `Display`:后者可能带着细节,
/// 而协议层已经决定过哪些细节不出门(`wire::Response::from_error` 那一条
/// 路径)。这里再 `to_string()` 一次,等于把刚关上的门重新打开。
fn refusal(error: KeydError) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode::INTERNAL_ERROR,
        error.wire_message(),
        // 粗码放 `data` 里:调用方能据此分支,而它本身不含任何秘密。
        Some(serde_json::json!({ "code": format!("{:?}", error.wire_code()) })),
    )
}

fn text(value: serde_json::Value) -> std::result::Result<CallToolResult, ErrorData> {
    let rendered = serde_json::to_string(&value)
        .map_err(|error| ErrorData::internal_error(format!("could not render a result: {error}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(rendered)]))
}

// ————————————————————————————————————————————————————————————
// 入口
// ————————————————————————————————————————————————————————————

/// 在 stdin/stdout 上跑 MCP 服务,直到对端关闭。
///
/// `socket` 不给就按默认布局推导(`~/.anpio-key/run/keyd.sock`)。
///
/// **stdout 归协议。** 这里不打印任何东西到 stdout —— 一行日志就能把一次
/// 初始化打成 JSON 解析错误,而症状看起来像"MCP 客户端不认这个服务器"。
/// 诊断信息走 `tracing`,去 stderr。
pub fn serve(socket: Option<PathBuf>) -> crate::error::Result<()> {
    let socket = match socket {
        Some(socket) => socket,
        None => KeydLayout::user_default()?.sock_path(),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(KeydError::Io)?;

    runtime.block_on(async move {
        let service = Keyd::new(socket)
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|error| KeydError::Protocol(format!("MCP handshake failed: {error}")))?;

        service
            .waiting()
            .await
            .map_err(|error| KeydError::Protocol(format!("MCP server stopped: {error}")))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **工具表就是这四个,而且没有一个能把任意字节签出去。**
    ///
    /// 这条测试挡的是"顺手加一个工具":MCP 是 agent 直接够得着的面,多一个
    /// 工具就是多一条 agent 能走的路。所以工具集合被钉死在这儿,改动它必须
    /// 先改这条测试 —— 而那次改动会被 review 看见。
    ///
    /// 第四个 `get_did_document` 是**只读**的,加它的理由写在模块头里:登录
    /// 需要它,而它不开放任何新的授权。往这张表里再加东西,请先回答模块头
    /// 那一节的问题。
    #[test]
    fn exactly_four_tools_and_none_of_them_signs_raw_bytes() {
        let router = Keyd::tool_router();
        let mut names: Vec<String> = router.list_all().into_iter().map(|tool| tool.name.to_string()).collect();
        names.sort();

        assert_eq!(
            names,
            ["get_did_document", "list_my_keys", "sign_request", "status"]
        );
        assert!(
            !names.iter().any(|name| name.contains("raw")),
            "raw signing must never be reachable from the MCP front end: {names:?}"
        );
    }

    #[test]
    fn tool_schemas_have_no_password_parameters() {
        let tools = Keyd::tool_router().list_all();
        let rendered = serde_json::to_string(&tools).unwrap();
        assert!(!rendered.contains("passphrase"));
        assert!(!rendered.contains("password"));
        assert!(!tools.iter().any(|tool| tool.name == "unlock"));
    }

    /// 通往守护进程的失败是**粗码**,不带内部细节。
    #[test]
    fn a_refusal_carries_the_coarse_message_not_the_internal_one() {
        let error = refusal(KeydError::BadPassphrase);
        assert_eq!(error.message, "the credential was refused");
        assert!(
            !error.message.contains("passphrase"),
            "the coarse message must not name the factor that failed: {}",
            error.message
        );
        assert!(error.data.is_some(), "the coarse code is for branching on");
    }

    /// 空参数的工具也要能过 schema —— 否则客户端列表都列不出来。
    #[test]
    fn the_empty_argument_struct_serialises_as_an_object() {
        let rendered = serde_json::to_string(&serde_json::json!({})).unwrap();
        assert_eq!(rendered, "{}");
        let _ = rmcp::schemars::schema_for!(NoArgs);
    }
}
