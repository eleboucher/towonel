use std::sync::Arc;

use prometheus::{IntCounter, IntCounterVec, IntGauge, Registry};
use towonel_common::metrics::{register_counter, register_counter_vec, register_gauge};

/// Reasons the hub rejects a signed config entry. Values become the
/// `reason=""` label on `towonel_hub_entries_rejected`; keep them stable —
/// dashboards and alerts query by these strings.
pub mod reject_reason {
    pub const INVALID_CBOR: &str = "invalid_cbor";
    pub const TENANT_NOT_ALLOWED: &str = "tenant_not_allowed";
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const UNSUPPORTED_OP: &str = "unsupported_op";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const INVALID_HOSTNAME: &str = "invalid_hostname";
    pub const HOSTNAME_NOT_OWNED: &str = "hostname_not_owned";
    pub const INVALID_TCP_SERVICE: &str = "invalid_tcp_service";
    pub const INVALID_TCP_PORT: &str = "invalid_tcp_port";
    pub const TCP_PORT_CLAIMED: &str = "tcp_port_claimed";
    pub const SEQUENCE_CONFLICT: &str = "sequence_conflict";
    pub const INTERNAL: &str = "internal";
}

/// Hub observability surface. Cheap to clone: the `prometheus` metric
/// types are internally `Arc`-shared and the `Registry` is held as an `Arc`.
#[derive(Clone)]
pub struct HubMetrics {
    pub entries_accepted: IntCounter,
    pub entries_rejected: IntCounterVec,
    pub sse_subscribers_connected: IntGauge,
    pub tenants_total: IntGauge,
    pub requests_total: IntCounterVec,
    registry: Arc<Registry>,
}

impl HubMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        towonel_common::process_metrics::register(&r);
        Self {
            entries_accepted: register_counter(
                &r,
                "towonel_hub_entries_accepted_total",
                "Signed config entries accepted by the hub",
            ),
            entries_rejected: register_counter_vec(
                &r,
                "towonel_hub_entries_rejected_total",
                "Signed config entries rejected by the hub, by reason",
                &["reason"],
            ),
            sse_subscribers_connected: register_gauge(
                &r,
                "towonel_hub_sse_subscribers_connected",
                "Currently connected /v1/routes/subscribe clients",
            ),
            tenants_total: register_gauge(
                &r,
                "towonel_hub_tenants_total",
                "Tenants currently active in the ownership policy",
            ),
            requests_total: register_counter_vec(
                &r,
                "towonel_hub_requests_total",
                "HTTP requests to the hub API, by matched route and response status",
                &["endpoint", "status"],
            ),
            registry: Arc::new(r),
        }
    }

    pub fn record_request(&self, endpoint: &str, status: u16) {
        let status_str = status.to_string();
        self.requests_total
            .with_label_values(&[endpoint, &status_str])
            .inc();
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn record_reject(&self, reason: &'static str) {
        self.entries_rejected.with_label_values(&[reason]).inc();
    }
}

impl Default for HubMetrics {
    fn default() -> Self {
        Self::new()
    }
}
