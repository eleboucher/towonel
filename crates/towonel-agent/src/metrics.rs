use std::sync::Arc;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use towonel_common::metrics::{
    register_counter, register_counter_family, register_gauge, register_gauge_family,
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

pub mod heartbeat_outcome {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";
}

pub mod direction {
    pub const EDGE_TO_ORIGIN: &str = "edge_to_origin";
    pub const ORIGIN_TO_EDGE: &str = "origin_to_edge";
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabel {
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutcomeLabel {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DirectionLabel {
    pub direction: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct InfoLabel {
    pub version: String,
}

#[derive(Clone)]
pub struct AgentMetrics {
    pub edge_connections_accepted: Counter,
    pub edge_connections_rejected: Counter,
    pub streams_accepted: Counter,
    pub streams_completed: Counter,
    pub stream_errors: Family<ReasonLabel, Counter>,
    pub streams_active: Gauge,
    pub bytes_total: Family<DirectionLabel, Counter>,
    pub heartbeats: Family<OutcomeLabel, Counter>,
    pub info: Family<InfoLabel, Gauge>,
    registry: Arc<Registry>,
}

impl AgentMetrics {
    pub fn new() -> Self {
        let mut r = Registry::default();
        Self {
            edge_connections_accepted: register_counter(
                &mut r,
                "towonel_agent_edge_connections_accepted",
                "iroh connections accepted from trusted edges",
            ),
            edge_connections_rejected: register_counter(
                &mut r,
                "towonel_agent_edge_connections_rejected",
                "iroh connections rejected because the remote is not a trusted edge",
            ),
            streams_accepted: register_counter(
                &mut r,
                "towonel_agent_streams_accepted",
                "Bi-directional streams opened by an edge",
            ),
            streams_completed: register_counter(
                &mut r,
                "towonel_agent_streams_completed",
                "Streams that finished forwarding without error",
            ),
            stream_errors: register_counter_family(
                &mut r,
                "towonel_agent_stream_errors",
                "Stream failures by reason",
            ),
            streams_active: register_gauge(
                &mut r,
                "towonel_agent_streams_active",
                "Streams currently being forwarded",
            ),
            bytes_total: register_counter_family(
                &mut r,
                "towonel_agent_bytes",
                "Bytes forwarded between edge and origin, by direction",
            ),
            heartbeats: register_counter_family(
                &mut r,
                "towonel_agent_heartbeats",
                "Heartbeat POSTs to the hub, by outcome",
            ),
            info: register_gauge_family(
                &mut r,
                "towonel_agent_info",
                "Agent build info; value is always 1",
            ),
            registry: Arc::new(r),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn set_info(&self, version: &str) {
        self.info
            .get_or_create(&InfoLabel {
                version: version.to_string(),
            })
            .set(1);
    }

    pub fn record_stream_error(&self, reason: &'static str) {
        self.stream_errors
            .get_or_create(&ReasonLabel {
                reason: reason.to_string(),
            })
            .inc();
    }

    pub fn record_heartbeat(&self, outcome: &'static str) {
        self.heartbeats
            .get_or_create(&OutcomeLabel {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub fn add_bytes(&self, dir: &'static str, n: u64) {
        self.bytes_total
            .get_or_create(&DirectionLabel {
                direction: dir.to_string(),
            })
            .inc_by(n);
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
    use prometheus_client::encoding::text::encode;
    use towonel_common::metrics::GaugeGuard;

    #[test]
    fn registry_encodes_all_series() {
        let m = AgentMetrics::new();
        m.set_info("test-0.0.0");
        m.edge_connections_accepted.inc();
        m.edge_connections_rejected.inc();
        m.streams_accepted.inc();
        m.streams_completed.inc();
        m.record_stream_error(stream_error::ORIGIN_CONNECT);
        m.add_bytes(direction::EDGE_TO_ORIGIN, 123);
        m.add_bytes(direction::ORIGIN_TO_EDGE, 456);
        m.record_heartbeat(heartbeat_outcome::OK);
        m.record_heartbeat(heartbeat_outcome::ERROR);

        let mut out = String::new();
        encode(&mut out, m.registry()).unwrap();

        for name in [
            "towonel_agent_edge_connections_accepted_total",
            "towonel_agent_edge_connections_rejected_total",
            "towonel_agent_streams_accepted_total",
            "towonel_agent_streams_completed_total",
            "towonel_agent_stream_errors_total",
            "towonel_agent_streams_active",
            "towonel_agent_bytes_total",
            "towonel_agent_heartbeats_total",
            "towonel_agent_info",
        ] {
            assert!(out.contains(name), "missing metric {name} in:\n{out}");
        }
        assert!(out.contains("reason=\"origin_connect\""));
        assert!(out.contains("direction=\"edge_to_origin\""));
        assert!(out.contains("outcome=\"ok\""));
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
