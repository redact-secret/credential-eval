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

/// Longest CPU model name recorded, in characters.
const MAX_CPU_MODEL: usize = 128;

/// Reduce a reported CPU model to a recordable name: printable ASCII from a
/// small safe set, runs of spaces collapsed, at most [`MAX_CPU_MODEL`]
/// characters. `None` when nothing is left.
pub fn sanitize_cpu_model(raw: &str) -> Option<String> {
    let kept: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " ()@.,-_/+".contains(*c))
        .collect();
    let collapsed = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = collapsed.chars().take(MAX_CPU_MODEL).collect();
    (!name.is_empty()).then_some(name)
}

/// The CPU model from `/proc/cpuinfo` text (the first `model name` line).
pub fn parse_cpuinfo_model(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model name")
            .then(|| sanitize_cpu_model(value))
            .flatten()
    })
}

/// The CPU model of this host, when it reports one.
pub fn cpu_model() -> Option<String> {
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        return parse_cpuinfo_model(&text);
    }
    let output = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()?;
    sanitize_cpu_model(&String::from_utf8_lossy(&output.stdout))
}

/// Host diagnostics, with the load average taken now as `load_before`.
pub fn diagnostics() -> HostDiagnostics {
    HostDiagnostics {
        os: component(std::env::consts::OS),
        arch: component(std::env::consts::ARCH),
        cpu_model: cpu_model(),
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
    fn cpu_models_are_sanitized() {
        let linux = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz\nmodel name\t: other\n";
        assert_eq!(
            parse_cpuinfo_model(linux).as_deref(),
            Some("Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz")
        );
        assert_eq!(parse_cpuinfo_model("processor : 0\n"), None);
        assert_eq!(
            sanitize_cpu_model("  Apple   M2 \n").as_deref(),
            Some("Apple M2")
        );
        // Anything outside the safe set is dropped, and the length is bounded.
        assert_eq!(
            sanitize_cpu_model("a\u{0}b\u{1b}[31mc<>|").as_deref(),
            Some("ab31mc")
        );
        assert_eq!(sanitize_cpu_model("한글"), None);
        assert_eq!(
            sanitize_cpu_model(&"x".repeat(500)).unwrap().len(),
            MAX_CPU_MODEL
        );
    }

    #[test]
    fn identifiers_are_valid_components() {
        let host = diagnostics();
        assert!(host.cpus >= 1);
        assert_eq!(component("x86_64").as_str(), "x86-64");
    }
}
