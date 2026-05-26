//! Prometheus standard `process_*` metrics (CPU, RSS, open FDs, start time).
//!
//! Thin wrapper over [`prometheus::process_collector::ProcessCollector`],
//! which uses `procfs` under the hood and is Linux-only. On non-Linux
//! platforms [`register`] is a no-op so calling it is safe from any OS.

/// Register the standard Prometheus `process_*` metrics on `registry`.
///
/// No-op on non-Linux platforms.
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::missing_const_for_fn,
        reason = "linux body uses non-const registry.register(); cfg shape must match"
    )
)]
pub fn register(
    #[cfg_attr(
        not(target_os = "linux"),
        expect(unused_variables, reason = "unused on non-linux platforms")
    )]
    registry: &prometheus::Registry,
) {
    #[cfg(target_os = "linux")]
    {
        let collector = prometheus::process_collector::ProcessCollector::for_self();
        #[expect(
            clippy::expect_used,
            reason = "duplicate registration is a startup-time programmer error"
        )]
        registry
            .register(Box::new(collector))
            .expect("process collector registers cleanly");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use prometheus::{Encoder, Registry, TextEncoder};

    #[test]
    fn scrape_emits_standard_process_series() {
        let registry = Registry::new();
        register(&registry);

        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buf)
            .expect("encode");
        let out = String::from_utf8(buf).expect("utf-8");

        for name in [
            "process_cpu_seconds_total",
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_open_fds",
            "process_max_fds",
            "process_start_time_seconds",
            "process_threads",
        ] {
            assert!(
                out.contains(name),
                "expected {name} in /metrics output; got:\n{out}"
            );
        }
    }
}
