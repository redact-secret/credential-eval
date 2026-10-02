//! Host diagnostics: operating system, architecture, CPUs and load average.
//!
//! Never records paths, user names or host names.

use credential_eval_contracts::ids::ComponentId;
use credential_eval_contracts::performance::{HostDiagnostics, LoadAverage};

fn component(raw: &str) -> ComponentId {
    let slug: String = raw
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    ComponentId::new(slug).unwrap_or_else(|_| ComponentId::new("unknown").expect("valid id"))
}

/// Parse `/proc/loadavg` (`0.12 0.34 0.56 1/234 5678`) or `sysctl -n vm.loadavg`
/// (`{ 0.12 0.34 0.56 }`).
pub fn parse_load_average(text: &str) -> Option<LoadAverage> {
    let numbers: Vec<f64> = text
        .split(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .filter(|part| !part.is_empty())
        .take(3)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let [one, five, fifteen] = numbers[..] else {
        return None;
    };
    (one.is_finite() && five.is_finite() && fifteen.is_finite()).then_some(LoadAverage {
        one,
        five,
        fifteen,
    })
}

/// The current load average, when the host reports one.
pub fn load_average() -> Option<LoadAverage> {
    if let Ok(text) = std::fs::read_to_string("/proc/loadavg") {
        return parse_load_average(&text);
    }
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    parse_load_average(&String::from_utf8_lossy(&output.stdout))
}

/// Host diagnostics, with the load average taken now as `load_before`.
pub fn diagnostics() -> HostDiagnostics {
    HostDiagnostics {
        os: component(std::env::consts::OS),
        arch: component(std::env::consts::ARCH),
        cpus: std::thread::available_parallelism()
            .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX)),
        load_before: load_average(),
        load_after: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_load_average_formats() {
        let linux = parse_load_average("0.12 0.34 0.56 1/234 5678\n").unwrap();
        assert_eq!((linux.one, linux.five, linux.fifteen), (0.12, 0.34, 0.56));
        let macos = parse_load_average("{ 40.5 38.25 30.0 }\n").unwrap();
        assert_eq!((macos.one, macos.five, macos.fifteen), (40.5, 38.25, 30.0));
        assert!(parse_load_average("").is_none());
        assert!(parse_load_average("a b c").is_none());
        assert!(parse_load_average("1 2").is_none());
        assert!(parse_load_average("NaN 1 2").is_none());
    }

    #[test]
    fn identifiers_are_valid_components() {
        let host = diagnostics();
        assert!(host.cpus >= 1);
        assert_eq!(component("x86_64").as_str(), "x86-64");
    }
}
