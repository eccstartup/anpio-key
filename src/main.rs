//! `anpio-key` 的可执行入口。
//!
//! 入口只做三件事:解析参数、把 `KeydError` 打成一句人能读的话、定退出码。
//! 真正的逻辑全在 [`anpio_key::cli`] 里 —— 那里可以被测试,`main` 不行。

use clap::Parser;

use anpio_key::cli::Cli;
use anpio_key::error::KeydError;

fn main() {
    let cli = Cli::parse();

    if let Err(error) = anpio_key::cli::run(cli) {
        eprintln!("anpio-key: {error}");
        // 错误链要展开。`thiserror` 的 `#[from]` 会让 io 错误缩成一句
        // "I/O error",而底下那句 `Permission denied (os error 13)` 才是
        // 真正有用的 —— 它得打出来。
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        std::process::exit(exit_code(&error));
    }
}

/// 退出码。
///
/// 只区分**"被拒"和"没做成"**两类:自动化要判断的是"守护进程拒绝了我"
/// (那是对端在说不行,重试没用),还是"这条命令本身没跑成"(可能是我传
/// 错了参数)。具体的错误码在消息里,不在退出码里 —— 退出码只有 8 位,
/// 塞不下协议的错误集,硬塞只会让 shell 脚本猜。
fn exit_code(error: &KeydError) -> i32 {
    match error {
        KeydError::Refused { .. } => 2,
        _ => 1,
    }
}
