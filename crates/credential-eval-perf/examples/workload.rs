//! Writes one generated synthetic workload to a file: `workload <id> <units> <out>`.
//!
//! For external measurement tooling (instruction counting, ADR 0002); the
//! input is synthetic and deterministic, and it is never printed.

use std::process::ExitCode;

use credential_eval_contracts::performance::WorkloadId;
use credential_eval_perf::workloads;

/// Largest workload this tool writes.
const MAX_BYTES: usize = 16 * 1024 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [id, units, out] = args.as_slice() else {
        eprintln!("usage: workload <workload-id> <units> <out-file>");
        return ExitCode::from(2);
    };
    let Ok(id) = serde_json::from_value::<WorkloadId>(serde_json::Value::String(id.clone())) else {
        eprintln!("unknown workload id");
        return ExitCode::from(2);
    };
    let Ok(units) = units.parse::<u32>() else {
        eprintln!("units must be a positive integer");
        return ExitCode::from(2);
    };
    match workloads::generate(id, units, MAX_BYTES) {
        Ok(text) => match std::fs::write(out, text) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cannot write: {e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
