//! Thin helpers around `prometheus-client` so each metrics module doesn't
//! repeat the `let x = Counter::default(); registry.register(name, help, x.clone())`
//! dance for every series.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

pub fn register_counter(registry: &mut Registry, name: &str, help: &str) -> Counter {
    let c = Counter::default();
    registry.register(name, help, c.clone());
    c
}

pub fn register_gauge(registry: &mut Registry, name: &str, help: &str) -> Gauge {
    let g = Gauge::default();
    registry.register(name, help, g.clone());
    g
}

pub fn register_counter_family<L>(
    registry: &mut Registry,
    name: &str,
    help: &str,
) -> Family<L, Counter>
where
    L: EncodeLabelSet + Clone + std::hash::Hash + Eq + std::fmt::Debug + Send + Sync + 'static,
{
    let f: Family<L, Counter> = Family::default();
    registry.register(name, help, f.clone());
    f
}

pub fn register_gauge_family<L>(registry: &mut Registry, name: &str, help: &str) -> Family<L, Gauge>
where
    L: EncodeLabelSet + Clone + std::hash::Hash + Eq + std::fmt::Debug + Send + Sync + 'static,
{
    let f: Family<L, Gauge> = Family::default();
    registry.register(name, help, f.clone());
    f
}

/// RAII handle that increments `gauge` on construction and decrements on
/// drop. Works for both normal client disconnect and task cancellation,
/// since `Drop` runs whenever the enclosing future is dropped.
pub struct GaugeGuard {
    gauge: Gauge,
}

impl GaugeGuard {
    #[must_use]
    pub fn inc(gauge: &Gauge) -> Self {
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

    #[test]
    fn gauge_guard_tracks_inc_and_dec() {
        let mut reg = Registry::default();
        let g = register_gauge(&mut reg, "test_active", "active things");
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
        let mut reg = Registry::default();
        let c = register_counter(&mut reg, "test_total", "total things");
        c.inc();
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &reg).unwrap();
        assert!(out.contains("test_total_total"), "missing series: {out}");
    }
}
