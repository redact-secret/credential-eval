//! Shared preparation for adapters that run a standalone scanner executable.

use std::ffi::OsString;
use std::time::Duration;

use credential_eval_contracts::config::{NetworkPolicy, ScannerSpec};
use credential_eval_contracts::observation::{ObservationResult, ScannerProvenance};
use serde_json::Value;

use crate::process::{self, CancelToken, ProcessRequest};
use crate::{
    AdapterEnv, PrepareFailure, Prepared, check_configuration, classify_probe, config_opt_str,
    config_str, fail, provenance, version_number,
};

/// What differs between executable adapters.
pub(crate) struct BinaryAdapter<'a> {
    /// Allowed configuration keys.
    pub allowed: &'a [&'static str],
    /// Configuration keys whose value is fixed by the adapter implementation.
    pub fixed: &'a [(&'static str, Value)],
    /// Arguments of the version probe.
    pub version_args: &'a [&'a str],
    /// Arguments that keep the scanner off the network (recorded).
    pub network_controls: &'a [&'a str],
}

/// Largest version-probe output retained.
const PROBE_STDOUT: u64 = 64 * 1024;

pub(crate) fn prepare(
    spec: &ScannerSpec,
    env: &AdapterEnv,
    cancel: &CancelToken,
    adapter: &BinaryAdapter<'_>,
) -> Result<Prepared, Box<PrepareFailure>> {
    let mut controls: Vec<String> = adapter
        .network_controls
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    controls.sort();
    controls.dedup();
    let mut provenance = ScannerProvenance {
        network: spec.network,
        network_controls: controls,
        components: Vec::new(),
    };
    if spec.network != NetworkPolicy::Disabled {
        return Err(fail(
            ObservationResult::Unsupported {
                reason: "adapter runs scanners with network disabled only".into(),
            },
            provenance,
        ));
    }
    let checked = check_configuration(spec, adapter.allowed, adapter.fixed).and_then(|()| {
        Ok((
            config_str(spec, "binary")?,
            config_opt_str(spec, "required_version")?,
        ))
    });
    let (binary, required) = checked.map_err(|result| fail(result, provenance.clone()))?;
    let Some(program) = provenance::which(binary, env.path.as_deref()) else {
        return Err(fail(
            ObservationResult::Unavailable {
                reason: "scanner executable not found".into(),
            },
            provenance,
        ));
    };
    let probe = process::run(
        &ProcessRequest {
            program: program.clone(),
            args: adapter.version_args.iter().map(OsString::from).collect(),
            cwd: env.cwd.clone(),
            stdin: None,
            timeout: Duration::from_millis(spec.limits.timeout_ms),
            max_stdout: PROBE_STDOUT.min(spec.limits.max_stdout_bytes),
            max_stderr: spec.limits.max_stderr_bytes,
        },
        cancel,
    );
    let process_time = probe.elapsed;
    let failure = |result, version, provenance| {
        Box::new(PrepareFailure {
            result,
            version,
            provenance,
            processes: 1,
            process_time,
        })
    };
    let stdout = match classify_probe(probe, &spec.limits) {
        Ok(stdout) => stdout,
        Err(result) => return Err(failure(result, None, provenance)),
    };
    let version = version_number(&String::from_utf8_lossy(&stdout));
    match provenance::executable(
        &provenance::program_name(binary),
        Some(version.clone()),
        &program,
    ) {
        Ok(component) => provenance.components.push(component),
        Err(_) => {
            return Err(failure(
                ObservationResult::Error {
                    reason: "scanner executable could not be digested".into(),
                },
                Some(version),
                provenance,
            ));
        }
    }
    if let Some(required) = required {
        if version != required {
            return Err(failure(
                ObservationResult::Unavailable {
                    reason: "installed scanner version does not match required_version".into(),
                },
                Some(version),
                provenance,
            ));
        }
    }
    Ok(Prepared {
        version: Some(version),
        provenance,
        program,
        prefix_args: Vec::new(),
        settings: Value::Null,
        processes: 1,
        process_time,
    })
}
