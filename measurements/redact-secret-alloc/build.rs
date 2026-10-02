//! Records the compiler that builds the harness (`rustc -vV`), so a run's
//! toolchain identity is the real one and not a claim.

use std::process::Command;

fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("-vV").output();
    let text = output
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map_or_else(|| "unknown".to_owned(), |v| v.trim().to_owned())
    };
    println!(
        "cargo:rustc-env=HARNESS_RUSTC_RELEASE={}",
        field("release:")
    );
    println!(
        "cargo:rustc-env=HARNESS_LLVM_VERSION={}",
        field("LLVM version:")
    );
    println!("cargo:rerun-if-changed=build.rs");
}
