use std::time::Duration;

pub fn positive_env(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be an integer"));
            assert!(value > 0, "{name} must be positive");
            value
        }
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("{name}: {error}"),
    }
}

pub fn percentile(sorted: &[Duration], percentile: usize) -> Duration {
    assert!(!sorted.is_empty());
    assert!((1..=100).contains(&percentile));
    sorted[(sorted.len() * percentile).div_ceil(100) - 1]
}

#[derive(Clone, Copy)]
pub struct Memory {
    pub resident_kib: Option<u64>,
    pub peak_kib: Option<u64>,
}

pub fn memory() -> Memory {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let field = |name| {
            status.lines().find_map(|line| {
                line.strip_prefix(name)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
        };
        Memory {
            resident_kib: field("VmRSS:"),
            peak_kib: field("VmHWM:"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Memory {
        resident_kib: None,
        peak_kib: None,
    }
}

pub fn mib(kib: Option<u64>) -> String {
    kib.map_or_else(
        || "unavailable".into(),
        |value| format!("{:.2}", value as f64 / 1024.0),
    )
}
