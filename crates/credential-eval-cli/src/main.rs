//! `credential-eval` command-line interface.
//!
//! Status: placeholder (issue #2). Only `--version` is implemented; the `run`
//! command arrives with issues #3, #4 and #7.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!(
                "{} {} (protocol {})",
                credential_eval_contracts::ENGINE_NAME,
                credential_eval_kernel::score::ENGINE_VERSION,
                credential_eval_contracts::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: credential-eval --version");
            eprintln!("(the run command is not implemented yet)");
            ExitCode::from(2)
        }
    }
}
