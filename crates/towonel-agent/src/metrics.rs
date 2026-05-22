use std::sync::Arc;

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry};
use towonel_common::metrics::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec,
};

/// Values become label strings on exported metrics; keep them stable so
/// dashboards and alerts keep matching.
pub mod stream_error {
    pub const HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
    pub const HANDSHAKE_ERROR: &str = "handshake_error";
    pub const NO_SERVICE: &str = "no_service";
    pub const ORIGIN_CONNECT: &str = "origin_connect";
    pub const FORWARD_ERROR: &str = "forward_error";
}

pub mod direction {
    pub const EDGE_TO_ORIGIN: &str = "edge_to_origin";
    pub const ORIGIN_TO_EDGE: &str = "origin_to_edge";
}

#[derive(Clone)]
pub struct AgentMetrics {
    pub edge_session_reconnects: IntCounterVec,
    pub edge_session_state: IntGaugeVec,
    pub streams_accepted: IntCounter,
    pub streams_completed: IntCounter,
    pub stream_errors: IntCounterVec,
    pub streams_active: IntGauge,
    pub bytes_total: IntCounterVec,
    pub info: IntGaugeVec,
    registry: Arc<Registry>,
}

impl AgentMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        towonel_common::process_metrics::register(&r);
        Self {
            edge_session_reconnects: register_counter_vec(
                &r,
                "towonel_agent_edge_session_reconnects_total",
                "Times the agent reconnected to an edge",
                &["edge"],
            ),
            edge_session_state: register_gauge_vec(
                &r,
                "towonel_agent_edge_session_state",
                "1 while a session to the edge is held, 0 otherwise",
                &["edge"],
            ),
            streams_accepted: register_counter(
                &r,
                "towonel_agent_streams_accepted_total",
                "Bi-directional streams opened by an edge",
            ),
            streams_completed: register_counter(
                &r,
                "towonel_agent_streams_completed_total",
                "Streams that finished forwarding without error",
            ),
            stream_errors: register_counter_vec(
                &r,
                "towonel_agent_stream_errors_total",
                "Stream failures by reason",
                &["reason"],
            ),
            streams_active: register_gauge(
                &r,
                "towonel_agent_streams_active",
                "Streams currently being forwarded",
            ),
            bytes_total: register_counter_vec(
                &r,
                "towonel_agent_bytes_total",
                "Bytes forwarded between edge and origin, by direction",
                &["direction"],
            ),
            info: register_gauge_vec(
                &r,
                "towonel_agent_info",
                "Agent build info; value is always 1",
                &["version"],
            ),
            registry: Arc::new(r),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn set_info(&self, version: &str) {
        self.info.with_label_values(&[version]).set(1);
    }

    pub fn record_stream_error(&self, reason: &'static str) {
        self.stream_errors.with_label_values(&[reason]).inc();
    }

    pub fn add_bytes(&self, dir: &'static str, n: u64) {
        self.bytes_total.with_label_values(&[dir]).inc_by(n);
    }
}

impl Default for AgentMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};
    use towonel_common::metrics::GaugeGuard;

    #[test]
    fn registry_encodes_all_series() {
        let m = AgentMetrics::new();
        m.set_info("test-0.0.0");
        m.streams_accepted.inc();
        m.streams_completed.inc();
        m.record_stream_error(stream_error::ORIGIN_CONNECT);
        m.add_bytes(direction::EDGE_TO_ORIGIN, 123);
        m.add_bytes(direction::ORIGIN_TO_EDGE, 456);

        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&m.registry().gather(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        for name in [
            "towonel_agent_streams_accepted",
            "towonel_agent_streams_completed",
            "towonel_agent_stream_errors",
            "towonel_agent_streams_active",
            "towonel_agent_bytes",
            "towonel_agent_info",
        ] {
            assert!(out.contains(name), "missing metric {name} in:\n{out}");
        }
        assert!(out.contains("reason=\"origin_connect\""));
        assert!(out.contains("direction=\"edge_to_origin\""));
        assert!(out.contains("version=\"test-0.0.0\""));
    }

    #[test]
    fn active_stream_guard_tracks_counts() {
        let m = AgentMetrics::new();
        assert_eq!(m.streams_active.get(), 0);
        {
            let _g1 = GaugeGuard::inc(&m.streams_active);
            let _g2 = GaugeGuard::inc(&m.streams_active);
            assert_eq!(m.streams_active.get(), 2);
        }
        assert_eq!(m.streams_active.get(), 0);
    }
}
