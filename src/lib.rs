//! anpio-key —— 持有 did:wba Ed25519 私钥、替 agent 签 RFC 9421 消息签名的本地守护进程。
//!
//! socket 不返回私钥；同 UID 任意代码执行的隔离取决于独立的部署边界。

#[cfg(all(not(debug_assertions), feature = "hardware-software"))]
compile_error!("hardware-software is a debug-only test double; release artifacts must exclude it");

pub mod audit;
pub mod cli;
pub mod client;
pub mod crypto;
pub mod daemon;
pub mod did;
pub mod error;
pub mod keystore;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod ops;
pub mod principal;
pub mod persistence;
pub mod security;
pub mod sign;
pub mod tty;

pub use error::{KeydError, Result};
