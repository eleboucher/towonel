use std::sync::Arc;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use towonel_common::metrics::{
    register_counter, register_counter_family, register_gauge, register_gauge_family,
};

/// Reasons the hub rejects a signed config entry. Values become the
/// `reason=""` label on `towonel_hub_entries_rejected`; keep them stable —
/// dashboards and alerts query by these strings.
pub mod reject_reason {
    pub const INVALID_CBOR: &str = "invalid_cbor";
    pub const TENANT_NOT_ALLOWED: &str = "tenant_not_allowed";
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const INVALID_HOSTNAME: &str = "invalid_hostname";
    pub const HOSTNAME_NOT_OWNED: &str = "hostname_not_owned";
    pub const SEQUENCE_CONFLICT: &str = "sequence_conflict";
    pub const INTERNAL: &str = "internal";
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EntryRejectLabels {
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerLabels {
    pub peer: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub endpoint: String,
    pub status: String,
}

/// Hub observability surface. Cheap to clone: all inner metrics hold `Arc`s.
#[derive(Clone)]
pub struct HubMetrics {
    pub entries_accepted: Counter,
    pub entries_rejected: Family<EntryRejectLabels, Counter>,
    pub federation_push_success: Family<PeerLabels, Counter>,
    pub federation_push_failures: Family<PeerLabels, Counter>,
    pub federation_push_last_ok_ms: Family<PeerLabels, Gauge>,
    pub sse_subscribers_connected: Gauge,
    pub tenants_total: Gauge,
    pub requests_total: Family<RequestLabels, Counter>,
    registry: Arc<Registry>,
}

impl HubMetrics {
    pub fn new() -> Self {
        let mut r = Registry::default();
        Self {
            entries_accepted: register_counter(
                &mut r,
                "towonel_hub_entries_accepted",
                "Signed config entries accepted by the hub",
            ),
            entries_rejected: register_counter_family(
                &mut r,
                "towonel_hub_entries_rejected",
                "Signed config entries rejected by the hub, by reason",
            ),
            federation_push_success: register_counter_family(
                &mut r,
                "towonel_hub_federation_push_success",
                "Outbound federation pushes that succeeded, per peer",
            ),
            federation_push_failures: register_counter_family(
                &mut r,
                "towonel_hub_federation_push_failures",
                "Outbound federation pushes that failed, per peer",
            ),
            federation_push_last_ok_ms: register_gauge_family(
                &mut r,
                "towonel_hub_federation_push_last_ok_ms",
                "Unix time (ms) of the last successful federation push, per peer",
            ),
            sse_subscribers_connected: register_gauge(
                &mut r,
                "towonel_hub_sse_subscribers_connected",
                "Currently connected /v1/routes/subscribe clients",
            ),
            tenants_total: register_gauge(
                &mut r,
                "towonel_hub_tenants_total",
                "Tenants currently active in the ownership policy",
            ),
            requests_total: register_counter_family(
                &mut r,
                "towonel_hub_requests",
                "HTTP requests to the hub API, by matched route and response status",
            ),
            registry: Arc::new(r),
        }
    }

    pub fn record_request(&self, endpoint: &str, status: u16) {
        self.requests_total
            .get_or_create(&RequestLabels {
                endpoint: endpoint.to_string(),
                status: status.to_string(),
            })
            .inc();
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn record_reject(&self, reason: &'static str) {
        self.entries_rejected
            .get_or_create(&EntryRejectLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    pub fn record_peer_push_success(&self, peer: &str, at_ms: u64) {
        let labels = PeerLabels {
            peer: peer.to_string(),
        };
        self.federation_push_success.get_or_create(&labels).inc();
        self.federation_push_last_ok_ms
            .get_or_create(&labels)
            .set(i64::try_from(at_ms).unwrap_or(i64::MAX));
    }

    pub fn record_peer_push_failure(&self, peer: &str) {
        self.federation_push_failures
            .get_or_create(&PeerLabels {
                peer: peer.to_string(),
            })
            .inc();
    }
}

impl Default for HubMetrics {
    fn default() -> Self {
        Self::new()
    }
}
