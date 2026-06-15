use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{Router, get};
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry, TextEncoder,
};
use serde::Serialize;
use towonel_common::identity::TenantId;
use towonel_common::metrics::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec,
};

/// Edge observability surface. Cheap to clone: the `prometheus` metric
/// types are internally `Arc`-shared and the `Registry` is held as an `Arc`.
#[derive(Clone)]
pub struct EdgeMetrics {
    pub active_connections: IntGauge,
    pub total_connections: IntCounter,
    pub total_bytes_in: IntCounter,
    pub total_bytes_out: IntCounter,
    pub active_sessions: IntGauge,
    pub sessions_total: IntCounter,
    pub sessions_rejected_total: IntCounterVec,
    pub route_no_session_total: IntCounter,
    /// Connections / sessions dropped because an edge concurrency cap was
    /// saturated, split by which cap fired.
    pub connections_rejected_overload: OverloadRejectCounters,
    /// Per-listener UDP drops, labelled `{tenant, service}` to attribute the
    /// otherwise-global `connections_rejected_overload` to a listener. Bounded
    /// by the active UDP-listener count.
    pub udp_sessions_rejected: IntCounterVec,
    pub udp_datagrams_dropped: IntCounterVec,
    /// Per-tenant mirrors of the global series above, labelled with the
    /// hex-encoded `TenantId`. Bounded by the active tenant count; the
    /// console scopes these server-side for the tenant dashboard.
    pub tenant_bytes: IntCounterVec,
    pub tenant_connections_total: IntCounterVec,
    pub tenant_active_sessions: IntGaugeVec,
    /// Resolved per-tenant counter children, so per-connection paths skip the
    /// hex encode of the tenant id and the label-map walk.
    tenant_children: Arc<papaya::HashMap<TenantId, TenantCounters>>,
    registry: Arc<Registry>,
}

/// Per-tenant children of the `tenant_*` counter vecs. Cheap to clone:
/// `prometheus` counters are internally `Arc`-shared.
#[derive(Clone)]
pub struct TenantCounters {
    pub bytes_in: IntCounter,
    pub bytes_out: IntCounter,
    pub connections_total: IntCounter,
}

/// Children of `towonel_edge_connections_rejected_overload_total`, one per
/// `reason`, pre-resolved at startup so the drop paths skip the label-map walk.
#[derive(Clone)]
pub struct OverloadRejectCounters {
    /// `TOWONEL_EDGE_MAX_INFLIGHT_CONNECTIONS` semaphore exhausted.
    pub tcp_inflight: IntCounter,
    /// Per-listener `TOWONEL_EDGE_MAX_UDP_SESSIONS_PER_LISTENER` cap hit.
    pub udp_session: IntCounter,
    /// Agent iroh-connection permit pool exhausted.
    pub iroh_agent: IntCounter,
}

impl OverloadRejectCounters {
    fn register(r: &Registry) -> Self {
        let vec = register_counter_vec(
            r,
            "towonel_edge_connections_rejected_overload_total",
            "Connections/sessions dropped because an edge concurrency cap was \
             saturated, by which cap fired (tcp_inflight = global inflight \
             semaphore, udp_session = per-listener UDP session cap, \
             iroh_agent = agent permit pool). Sustained values mean an \
             accept-time DoS or an under-sized cap.",
            &["reason"],
        );
        Self {
            tcp_inflight: vec.with_label_values(&[overload_reject_reason::TCP_INFLIGHT]),
            udp_session: vec.with_label_values(&[overload_reject_reason::UDP_SESSION]),
            iroh_agent: vec.with_label_values(&[overload_reject_reason::IROH_AGENT]),
        }
    }
}

impl EdgeMetrics {
    pub fn new() -> Self {
        let r = Registry::new();
        towonel_common::process_metrics::register(&r);
        Self {
            active_connections: register_gauge(
                &r,
                "towonel_edge_active_connections",
                "Active tunneled connections",
            ),
            total_connections: register_counter(
                &r,
                "towonel_edge_connections_total",
                "Total connections handled",
            ),
            total_bytes_in: register_counter(
                &r,
                "towonel_edge_bytes_in_total",
                "Total bytes received from clients",
            ),
            total_bytes_out: register_counter(
                &r,
                "towonel_edge_bytes_out_total",
                "Total bytes sent to clients",
            ),
            active_sessions: register_gauge(
                &r,
                "towonel_edge_active_sessions",
                "Agent iroh sessions currently registered with this edge",
            ),
            sessions_total: register_counter(
                &r,
                "towonel_edge_sessions_total",
                "Agent iroh sessions registered (each reconnect counts once)",
            ),
            sessions_rejected_total: register_counter_vec(
                &r,
                "towonel_edge_sessions_rejected_total",
                "Inbound iroh connections rejected, by reason",
                &["reason"],
            ),
            route_no_session_total: register_counter(
                &r,
                "towonel_edge_route_no_session_total",
                "Requests where no session was registered for the agent at lookup time \
                 (excludes the case where a session existed but its open_bi failed)",
            ),
            connections_rejected_overload: OverloadRejectCounters::register(&r),
            udp_sessions_rejected: register_counter_vec(
                &r,
                "towonel_edge_udp_sessions_rejected_total",
                "New UDP sessions refused at the per-listener \
                 TOWONEL_EDGE_MAX_UDP_SESSIONS_PER_LISTENER cap, by listener.",
                &["tenant", "service"],
            ),
            udp_datagrams_dropped: register_counter_vec(
                &r,
                "towonel_edge_udp_datagrams_dropped_total",
                "Datagrams dropped on an established UDP session because its send \
                 queue was full (the QUIC pump fell behind), by listener.",
                &["tenant", "service"],
            ),
            tenant_bytes: register_counter_vec(
                &r,
                "towonel_edge_tenant_bytes_total",
                "Bytes forwarded for a tenant, by direction relative to the client \
                 (in = client to edge, out = edge to client)",
                &["tenant", "direction"],
            ),
            tenant_connections_total: register_counter_vec(
                &r,
                "towonel_edge_tenant_connections_total",
                "Connections and UDP sessions routed to a tenant's agents \
                 (counted at successful agent pick, so unroutable junk is excluded)",
                &["tenant"],
            ),
            tenant_active_sessions: register_gauge_vec(
                &r,
                "towonel_edge_tenant_active_sessions",
                "Agent iroh connections currently held per tenant \
                 (the same slots the per-tenant session limit counts)",
                &["tenant"],
            ),
            tenant_children: Arc::new(papaya::HashMap::new()),
            registry: Arc::new(r),
        }
    }

    /// Resolved counter children for a tenant, cached after the first call.
    pub fn tenant_counters(&self, tenant: &TenantId) -> TenantCounters {
        let map = self.tenant_children.pin();
        if let Some(c) = map.get(tenant) {
            return c.clone();
        }
        let t = tenant.to_string();
        let counters = TenantCounters {
            bytes_in: self.tenant_bytes.with_label_values(&[&t, "in"]),
            bytes_out: self.tenant_bytes.with_label_values(&[&t, "out"]),
            connections_total: self.tenant_connections_total.with_label_values(&[&t]),
        };
        map.get_or_insert_with(*tenant, || counters.clone()).clone()
    }

    /// Drop a tenant's per-tenant series so tenant churn doesn't grow metric
    /// cardinality without bound. Called when a tenant's last session ends.
    pub fn evict_tenant(&self, tenant: &TenantId) {
        let t = tenant.to_string();
        // Err just means the label was never created; ignore it.
        _ = self.tenant_active_sessions.remove_label_values(&[&t]);
        _ = self.tenant_bytes.remove_label_values(&[&t, "in"]);
        _ = self.tenant_bytes.remove_label_values(&[&t, "out"]);
        _ = self.tenant_connections_total.remove_label_values(&[&t]);
        self.tenant_children.pin().remove(tenant);
    }

    /// Record forwarded bytes against the tenant's series. Call once per
    /// connection, not per chunk.
    pub fn record_tenant_bytes(&self, tenant: &TenantId, bytes_in: u64, bytes_out: u64) {
        let counters = self.tenant_counters(tenant);
        counters.bytes_in.inc_by(bytes_in);
        counters.bytes_out.inc_by(bytes_out);
    }
}

pub mod session_reject_reason {
    pub const UNKNOWN_AGENT: &str = "unknown_agent";
    pub const HANDSHAKE_ERROR: &str = "handshake_error";
    pub const PER_TENANT_LIMIT: &str = "per_tenant_limit";
}

pub mod overload_reject_reason {
    pub const TCP_INFLIGHT: &str = "tcp_inflight";
    pub const UDP_SESSION: &str = "udp_session";
    pub const IROH_AGENT: &str = "iroh_agent";
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    active_connections: i64,
    total_connections: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
}

async fn health(State(metrics): State<EdgeMetrics>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        active_connections: metrics.active_connections.get(),
        total_connections: metrics.total_connections.get(),
        total_bytes_in: metrics.total_bytes_in.get(),
        total_bytes_out: metrics.total_bytes_out.get(),
    })
}

async fn metrics_handler(State(metrics): State<EdgeMetrics>) -> impl IntoResponse {
    let mut buf = Vec::new();
    if let Err(e) = TextEncoder::new().encode(&metrics.registry.gather(), &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encoding failed: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buf,
    )
        .into_response()
}

pub fn router(metrics: EdgeMetrics) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}

async fn readyz(State(metrics): State<EdgeMetrics>) -> impl IntoResponse {
    // Edge is "ready" once at least one agent session has registered.
    // Before that, an LB would route traffic that has nowhere to go.
    if metrics.active_sessions.get() > 0 {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no agent sessions").into_response()
    }
}
