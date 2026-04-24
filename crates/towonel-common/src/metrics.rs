//! Thin helpers around the `prometheus` crate so each metrics module doesn't
//! repeat the construction + registration dance for every series.
//!
//! All `register_*` helpers panic on duplicate names or invalid identifiers
//! — both would be programmer errors caught immediately in a test run.

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

#[must_use]
pub fn register_counter(registry: &Registry, name: &str, help: &str) -> IntCounter {
    #[allow(clippy::expect_used)]
    let c = IntCounter::new(name, help).expect("valid metric identifier");
    #[allow(clippy::expect_used)]
    registry
        .register(Box::new(c.clone()))
        .expect("unique metric name");
    c
}

#[must_use]
pub fn register_gauge(registry: &Registry, name: &str, help: &str) -> IntGauge {
    #[allow(clippy::expect_used)]
    let g = IntGauge::new(name, help).expect("valid metric identifier");
    #[allow(clippy::expect_used)]
    registry
        .register(Box::new(g.clone()))
        .expect("unique metric name");
    g
}

#[must_use]
pub fn register_counter_vec(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
) -> IntCounterVec {
    #[allow(clippy::expect_used)]
    let v = IntCounterVec::new(Opts::new(name, help), labels).expect("valid metric identifier");
    #[allow(clippy::expect_used)]
    registry
        .register(Box::new(v.clone()))
        .expect("unique metric name");
    v
}

#[must_use]
pub fn register_gauge_vec(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
) -> IntGaugeVec {
    #[allow(clippy::expect_used)]
    let v = IntGaugeVec::new(Opts::new(name, help), labels).expect("valid metric identifier");
    #[allow(clippy::expect_used)]
    registry
        .register(Box::new(v.clone()))
        .expect("unique metric name");
    v
}

/// RAII: increments on `inc`, decrements on drop. Survives task
/// cancellation since `Drop` runs when the enclosing future is dropped.
pub struct GaugeGuard {
    gauge: IntGauge,
}

impl GaugeGuard {
    #[must_use]
    pub fn inc(gauge: &IntGauge) -> Self {
        gauge.inc();
        Self {
            gauge: gauge.clone(),
        }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};

    #[test]
    fn gauge_guard_tracks_inc_and_dec() {
        let reg = Registry::new();
        let g = register_gauge(&reg, "test_active", "active things");
        assert_eq!(g.get(), 0);
        {
            let _a = GaugeGuard::inc(&g);
            let _b = GaugeGuard::inc(&g);
            assert_eq!(g.get(), 2);
        }
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn counter_helper_registers_series() {
        let reg = Registry::new();
        let c = register_counter(&reg, "test_total", "total things");
        c.inc();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&reg.gather(), &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("test_total"), "missing series: {out}");
    }
}
