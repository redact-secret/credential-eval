//! The real Node shim against a fake package: output volume, order and
//! multiplicity are exactly the one-line-per-finding stream, including when
//! the reader is slower than the writer.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

const FINDINGS_PER_FILE: usize = 40_000;

fn shim() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../adapters/node/shim.mjs")
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A `flare-redact` stand-in reporting `FINDINGS_PER_FILE` findings per text,
/// the same range repeated (multiplicity must survive) and then varied.
fn package(root: &std::path::Path) {
    let dir = root.join("node_modules/flare-redact");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"flare-redact","version":"0.0.0-fake","type":"module","main":"index.js"}"#,
    )
    .unwrap();
    fs::write(
        dir.join("index.js"),
        format!(
            "export function scan(text) {{
  const out = [];
  for (let i = 0; i < {FINDINGS_PER_FILE}; i++) {{
    const start = i < 10 ? 0 : i % 7;
    out.push({{ start, end: start + 3, detector: 'aws_secret_key' }});
  }}
  return out;
}}
"
        ),
    )
    .unwrap();
}

#[test]
fn slow_reader_receives_every_finding_in_order() {
    if !node_available() {
        eprintln!("skipped: node is not installed");
        return;
    }
    let root = std::env::temp_dir().join(format!("cieval-shim-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("fixtures")).unwrap();
    package(&root);
    let paths = ["a.txt", "b.txt", "c.txt"];
    for path in paths {
        fs::write(root.join("fixtures").join(path), "abcdefghij").unwrap();
    }
    let request = serde_json::json!({
        "root": root.join("fixtures"),
        "paths": paths,
        "options": {},
    });

    let mut child = Command::new("node")
        .arg(shim())
        .args(["scan", "flare-redact"])
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    // A reader far slower than the writer: the shim must wait, not buffer
    // without bound or drop output.
    let mut stdout = child.stdout.take().unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stdout.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(child.wait().unwrap().success());

    let mut expected = String::new();
    for path in paths {
        for i in 0..FINDINGS_PER_FILE {
            let start = if i < 10 { 0 } else { i % 7 };
            expected.push_str(&format!(
                "{{\"path\":\"{path}\",\"start\":{start},\"end\":{},\"label\":\"aws_secret_key\"}}\n",
                start + 3
            ));
        }
    }
    expected.push_str(&format!(
        "{{\"done\":true,\"findings\":{}}}\n",
        paths.len() * FINDINGS_PER_FILE
    ));
    assert!(
        out == expected.as_bytes(),
        "shim output differs from the one-line-per-finding stream"
    );
    let _ = fs::remove_dir_all(&root);
}
