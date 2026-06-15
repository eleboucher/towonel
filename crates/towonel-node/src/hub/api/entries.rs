use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use serde::Serialize;
use towonel_common::config_entry::{ConfigEntryError, ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::TenantId;
use tracing::warn;

use towonel_common::time::now_ms;

use super::super::db::port_reservations::PortProtocol;
use super::super::metrics::reject_reason;
use super::{
    AppState, MAX_CLOCK_SKEW_MS, PROTOCOL_VERSION, Pagination, apply_port_index_delta,
    cbor_response, constant_time_eq, error_response, hostname_not_owned, internal_error,
    invalid_request, invalid_signature, json_ok, json_ok_paged, paginate,
    remove_tenant_from_port_index, sequence_conflict, tenant_not_allowed, trigger_route_rebuild,
    unauthorized, unsupported_op, unsupported_version,
};

#[derive(Serialize)]
struct PostEntryResponse {
    status: &'static str,
    sequence: u64,
}

/// Discriminator for the two protocol-flavored service ops. Lets the
/// service-name + port validation share one code path across TCP and UDP.
#[derive(Clone, Copy)]
enum ServiceKind {
    Tcp,
    Udp,
}

/// Per-protocol labels + reject reasons, picked once via [`ServiceKind::reasons`].
struct Reasons {
    label: &'static str,
    invalid_service: &'static str,
    invalid_port: &'static str,
    port_claimed: &'static str,
}

impl ServiceKind {
    const fn reasons(self) -> Reasons {
        match self {
            Self::Tcp => Reasons {
                label: "tcp",
                invalid_service: reject_reason::INVALID_TCP_SERVICE,
                invalid_port: reject_reason::INVALID_TCP_PORT,
                port_claimed: reject_reason::TCP_PORT_CLAIMED,
            },
            Self::Udp => Reasons {
                label: "udp",
                invalid_service: reject_reason::INVALID_UDP_SERVICE,
                invalid_port: reject_reason::INVALID_UDP_PORT,
                port_claimed: reject_reason::UDP_PORT_CLAIMED,
            },
        }
    }
}

/// Service names are operator-chosen opaque labels — only reject what would
/// break wire format or logs.
fn validate_service_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("must not be empty");
    }
    if name.len() > 64 {
        return Err("must be 64 bytes or fewer");
    }
    if name.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(())
}

/// Set `TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS=true` to let tenants claim ports
/// below 1024. Default off — protects against a tenant accidentally claiming
/// 22, 80, 443 etc. and breaking other services on the edge box.
const ALLOW_PRIVILEGED_PORTS_ENV: &str = "TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS";

fn allow_privileged_ports() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var(ALLOW_PRIVILEGED_PORTS_ENV)
            .ok()
            .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    })
}

fn validate_listen_port(port: u16) -> Result<(), &'static str> {
    if port == 0 {
        return Err("must not be 0");
    }
    if port < 1024 && !allow_privileged_ports() {
        return Err(
            "privileged ports (<1024) are blocked; set TOWONEL_HUB_ALLOW_PRIVILEGED_PORTS=true to override",
        );
    }
    Ok(())
}

/// Reason the requested `(tenant, service, listen_port)` triple can't be
/// inserted. Re-publishing the same `(service, port)` for the same tenant
/// is allowed and returns no conflict.
enum PortConflict {
    OtherTenant { tenant: TenantId },
    SameTenantOtherService { service: String },
}

/// Look up `listen_port` in the cached per-protocol port index. The cache is
/// refreshed by `rebuild_and_broadcast_routes` after every upsert/delete and
/// computed without the liveness filter, so an agent that's currently
/// disconnected still owns its declared port.
fn find_port_conflict(
    port_index: &super::PortIndex,
    kind: ServiceKind,
    listen_port: u16,
    requesting_tenant: &TenantId,
    requesting_service: &str,
) -> Option<PortConflict> {
    let map = match kind {
        ServiceKind::Tcp => &port_index.tcp,
        ServiceKind::Udp => &port_index.udp,
    };
    let (tenant, service) = map.get(&listen_port)?;
    if tenant != requesting_tenant {
        return Some(PortConflict::OtherTenant { tenant: *tenant });
    }
    if service != requesting_service {
        return Some(PortConflict::SameTenantOtherService {
            service: service.clone(),
        });
    }
    None
}

async fn require_reservation(
    state: &Arc<AppState>,
    kind: ServiceKind,
    listen_port: u16,
    tenant_id: &TenantId,
) -> Result<(), Response> {
    let protocol = match kind {
        ServiceKind::Tcp => PortProtocol::Tcp,
        ServiceKind::Udp => PortProtocol::Udp,
    };
    let owns = state
        .db
        .tenant_owns_port(tenant_id, listen_port, protocol)
        .await
        .map_err(|e| {
            warn!(error = %e, "tenant_owns_port query failed");
            internal_error()
        })?;
    if owns {
        return Ok(());
    }
    state
        .metrics
        .record_reject(reject_reason::PORT_NOT_RESERVED);
    Err(error_response(
        axum::http::StatusCode::FORBIDDEN,
        "port_not_reserved",
        format!(
            "tenant has no {} reservation for listen_port {listen_port}; \
             reserve via POST /v1/tenants/{tenant_id}/ports first",
            kind.reasons().label,
        ),
    ))
}

async fn validate_service_op(
    state: &Arc<AppState>,
    payload: &ConfigPayload,
) -> Result<(), Response> {
    let service_op = match &payload.op {
        ConfigOp::UpsertTcpService { service, .. } | ConfigOp::DeleteTcpService { service } => {
            Some((ServiceKind::Tcp, service.as_str()))
        }
        ConfigOp::UpsertUdpService { service, .. } | ConfigOp::DeleteUdpService { service } => {
            Some((ServiceKind::Udp, service.as_str()))
        }
        _ => None,
    };
    if let Some((kind, service)) = service_op
        && let Err(e) = validate_service_name(service)
    {
        let r = kind.reasons();
        state.metrics.record_reject(r.invalid_service);
        return Err(invalid_request(format!(
            "invalid {} service name `{service}`: {e}",
            r.label
        )));
    }

    let upsert = match &payload.op {
        ConfigOp::UpsertTcpService { listen_port, .. } => Some((ServiceKind::Tcp, *listen_port)),
        ConfigOp::UpsertUdpService { listen_port, .. } => Some((ServiceKind::Udp, *listen_port)),
        _ => None,
    };
    if let Some((kind, listen_port)) = upsert {
        let r = kind.reasons();
        if let Err(e) = validate_listen_port(listen_port) {
            state.metrics.record_reject(r.invalid_port);
            return Err(invalid_request(format!(
                "invalid {} listen_port {listen_port}: {e}",
                r.label
            )));
        }
        if state.ports_require_reservation
            && let Err(resp) =
                require_reservation(state, kind, listen_port, &payload.tenant_id).await
        {
            return Err(resp);
        }
    }
    Ok(())
}

/// Cross-tenant port-uniqueness check against the cached index. Kept separate
/// from [`validate_service_op`] so only this — plus the entry insert and the
/// index update — runs under the per-protocol port lock.
fn check_port_conflict(state: &AppState, payload: &ConfigPayload) -> Option<Response> {
    let (kind, service, listen_port) = match &payload.op {
        ConfigOp::UpsertTcpService {
            service,
            listen_port,
        } => (ServiceKind::Tcp, service.as_str(), *listen_port),
        ConfigOp::UpsertUdpService {
            service,
            listen_port,
        } => (ServiceKind::Udp, service.as_str(), *listen_port),
        _ => return None,
    };
    let r = kind.reasons();
    match find_port_conflict(
        &state.port_index.load(),
        kind,
        listen_port,
        &payload.tenant_id,
        service,
    ) {
        None => None,
        Some(PortConflict::OtherTenant { tenant }) => {
            state.metrics.record_reject(r.port_claimed);
            Some(invalid_request(format!(
                "{} listen_port {listen_port} is already claimed by tenant {tenant}",
                r.label
            )))
        }
        Some(PortConflict::SameTenantOtherService {
            service: other_service,
        }) => {
            state.metrics.record_reject(r.port_claimed);
            Some(invalid_request(format!(
                "{} listen_port {listen_port} is already bound to service `{other_service}` for this tenant",
                r.label
            )))
        }
    }
}

/// `POST /v1/entries`
///
/// Validation pipeline per protocol section 4.3:
/// 1. parse CBOR body
/// 2. tenant allowlist check (cheap -- fail before crypto)
/// 3. ML-DSA-65 signature verification
/// 4. inner/outer `tenant_id` match
/// 5. payload version check
/// 6. hostname ownership check (for hostname ops only)
/// 7. sequence uniqueness (DB UNIQUE constraint)
#[expect(
    clippy::too_many_lines,
    reason = "linear validation pipeline for config entries"
)]
pub(super) async fn post_entry(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let entry: SignedConfigEntry = match ciborium::from_reader(body.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            state.metrics.record_reject(reject_reason::INVALID_CBOR);
            return invalid_request(format!("invalid CBOR body: {e}"));
        }
    };

    let policy = state.policy.load_full();

    let Some(pq_pubkey) = policy.pq_public_key(&entry.tenant_id) else {
        state
            .metrics
            .record_reject(reject_reason::TENANT_NOT_ALLOWED);
        return tenant_not_allowed("tenant is not on the operator's allowlist");
    };

    let payload: ConfigPayload = match entry.verify(pq_pubkey) {
        Ok(p) => p,
        Err(e @ ConfigEntryError::Decode(_)) => {
            state.metrics.record_reject(reject_reason::UNSUPPORTED_OP);
            return unsupported_op(e.to_string());
        }
        Err(e @ ConfigEntryError::UnsupportedVersion(_)) => {
            state
                .metrics
                .record_reject(reject_reason::UNSUPPORTED_VERSION);
            return unsupported_version(e.to_string());
        }
        Err(e) => {
            state
                .metrics
                .record_reject(reject_reason::INVALID_SIGNATURE);
            return invalid_signature(e.to_string());
        }
    };

    // No redundant version re-check here: `entry.verify` above already rejected
    // any unsupported version (both enforce CONFIG_PAYLOAD_VERSION).

    let hostname_for_check = match &payload.op {
        ConfigOp::UpsertHostname { hostname }
        | ConfigOp::DeleteHostname { hostname }
        | ConfigOp::SetHostnameTls { hostname, .. } => Some(hostname),
        ConfigOp::UpsertAgent { .. }
        | ConfigOp::RevokeAgent { .. }
        | ConfigOp::UpsertTcpService { .. }
        | ConfigOp::DeleteTcpService { .. }
        | ConfigOp::UpsertUdpService { .. }
        | ConfigOp::DeleteUdpService { .. } => None,
    };
    if let Some(hostname) = hostname_for_check {
        if let Err(e) = towonel_common::hostname::validate_hostname(hostname) {
            state.metrics.record_reject(reject_reason::INVALID_HOSTNAME);
            return invalid_request(format!("invalid hostname `{hostname}`: {e}"));
        }
        if !policy.is_hostname_allowed(&payload.tenant_id, hostname) {
            state
                .metrics
                .record_reject(reject_reason::HOSTNAME_NOT_OWNED);
            return hostname_not_owned(format!(
                "tenant is not authorized for hostname: {hostname}"
            ));
        }
    }

    // Validation + reservation lookup run outside the port lock; they don't
    // race other upserts.
    if let Err(resp) = validate_service_op(&state, &payload).await {
        return resp;
    }

    // Idempotency check for UpsertAgent: if this agent is already registered,
    // return success without inserting a duplicate entry. This eliminates
    // sequence conflicts when multiple agent replicas boot simultaneously.
    if let ConfigOp::UpsertAgent { agent_id } = &payload.op {
        match state
            .db
            .is_agent_registered(&payload.tenant_id, agent_id, pq_pubkey)
            .await
        {
            Ok(true) => {
                state.metrics.entries_accepted.inc();
                return cbor_response(&PostEntryResponse {
                    status: "ok",
                    sequence: payload.sequence,
                });
            }
            Ok(false) => {}
            Err(e) => {
                state.metrics.record_reject(reject_reason::INTERNAL);
                warn!(error = %e, "failed to check agent registration status");
                return internal_error();
            }
        }
    }

    // Lock only the conflict-check → insert → index-update window so the
    // cross-tenant port claim is atomic. TCP and UDP have separate locks
    // because they share no port namespace at the OS level.
    let _port_guard = match &payload.op {
        ConfigOp::UpsertTcpService { .. } => Some(state.tcp_port_lock.lock().await),
        ConfigOp::UpsertUdpService { .. } => Some(state.udp_port_lock.lock().await),
        _ => None,
    };
    if let Some(resp) = check_port_conflict(&state, &payload) {
        return resp;
    }

    let sequence = payload.sequence;

    if let Err(e) = state.db.insert(&entry, sequence).await {
        if super::db::is_unique_violation(&e) {
            state
                .metrics
                .record_reject(reject_reason::SEQUENCE_CONFLICT);
            return sequence_conflict("sequence number already used by this tenant");
        }
        state.metrics.record_reject(reject_reason::INTERNAL);
        warn!(error = %e, "failed to insert entry");
        return internal_error();
    }

    state.metrics.entries_accepted.inc();

    // Only service ops touch the port index; update it incrementally so the
    // next find_port_conflict sees this claim without a full rescan. Still
    // under `_port_guard`, so this is serialized against same-protocol claims.
    match &payload.op {
        ConfigOp::UpsertTcpService { .. }
        | ConfigOp::DeleteTcpService { .. }
        | ConfigOp::UpsertUdpService { .. }
        | ConfigOp::DeleteUdpService { .. } => {
            apply_port_index_delta(&state, payload.tenant_id, &payload.op);
        }
        _ => {}
    }
    trigger_route_rebuild(&state);

    cbor_response(&PostEntryResponse {
        status: "ok",
        sequence,
    })
}

/// `Some(rejection)` when the caller may not read tenant `tenant_id`'s
/// entries, `None` otherwise. Accepts the operator API key (`Bearer`) or an
/// ML-DSA signature proving possession of the tenant key (`Signature`).
fn authorize_tenant_read(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    tenant_id: &TenantId,
) -> Option<Response> {
    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Some(unauthorized("missing Authorization header"));
    };

    if let Some(token) = auth.strip_prefix("Bearer ")
        && constant_time_eq(token.as_bytes(), state.operator_api_key.as_bytes())
    {
        return None;
    }

    let policy = state.policy.load();
    match towonel_common::auth::verify_tenant_request_header(
        auth,
        towonel_common::auth::TENANT_REQUEST_AUTH_DOMAIN,
        towonel_common::time::now_ms(),
        MAX_CLOCK_SKEW_MS,
        |tid| policy.pq_public_key(tid).cloned(),
    ) {
        Ok(signer) if &signer == tenant_id => None,
        Ok(_) => Some(unauthorized(
            "signature tenant does not match requested tenant",
        )),
        Err(msg) => Some(unauthorized(msg)),
    }
}

pub(super) async fn get_tenant_entries(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    if let Some(resp) = authorize_tenant_read(&state, &headers, &tenant_id) {
        return resp;
    }

    let entries = match state.db.get_entries(&tenant_id).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "failed to query entries");
            return internal_error();
        }
    };

    cbor_response(&entries)
}

pub(super) async fn health(State(state): State<Arc<AppState>>) -> Response {
    #[derive(Serialize)]
    struct HealthResponse<'a> {
        status: &'a str,
        node_id: iroh::EndpointId,
        version: &'a str,
        protocol_version: u16,
    }
    json_ok(HealthResponse {
        status: "ok",
        node_id: state.identity.node_id,
        version: state.identity.software_version,
        protocol_version: PROTOCOL_VERSION,
    })
}

/// Kubernetes-style readiness probe: returns 503 unless the hub can talk to
/// its database. `/v1/health` only confirms the process is alive; rollout
/// controllers and load balancers should hit `/v1/readyz` instead so a hub
/// that has lost its DB connection is taken out of rotation immediately.
pub(super) async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    use sea_orm::{ConnectionTrait, Statement};
    // Only the leader holds the edge hub-links and the live_edges snapshot
    // bootstrap serves; keep standbys out of the Service rotation.
    if !state.is_leader.load(std::sync::atomic::Ordering::Relaxed) {
        return error_response(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "not_ready",
            "not the leader",
        );
    }
    let backend = state.db.conn.get_database_backend();
    match state
        .db
        .conn
        .execute(Statement::from_string(backend, "SELECT 1".to_string()))
        .await
    {
        Ok(_) => json_ok(serde_json::json!({"status": "ok"})),
        Err(e) => {
            warn!(error = %e, "readyz DB ping failed");
            error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "not_ready",
                "database unreachable",
            )
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/edges",
    tag = "operator",
    params(
        ("limit" = Option<usize>, Query, description = "Page size; omit to return all"),
        ("offset" = Option<usize>, Query, description = "Page offset (default 0)"),
    ),
    responses((status = 200, description = "Edge nodes known to the hub; total in X-Total-Count")),
    security(("operator_key" = [])),
)]
pub(super) async fn list_edges(
    State(state): State<Arc<AppState>>,
    Query(page): Query<Pagination>,
) -> Response {
    #[derive(Serialize)]
    struct EdgeEntry {
        node_id: iroh::EndpointId,
        addresses: Vec<String>,
    }
    #[derive(Serialize)]
    struct ListEdgesResponse {
        edges: Vec<EdgeEntry>,
    }

    let mut edges: Vec<EdgeEntry> = Vec::new();
    if let Some(self_edge) = state.identity.edge_node_id {
        edges.push(EdgeEntry {
            node_id: self_edge,
            addresses: state.identity.edge_addresses.clone(),
        });
    }
    for (edge_id, iroh_endpoints, _, _, _) in state.live_edges.snapshot() {
        if let Ok(node_id) = iroh::EndpointId::from_bytes(&edge_id)
            && !edges.iter().any(|e| e.node_id == node_id)
        {
            edges.push(EdgeEntry {
                node_id,
                addresses: iroh_endpoints,
            });
        }
    }

    let (edges, total) = paginate(edges, &page);
    json_ok_paged(ListEdgesResponse { edges }, total)
}

/// `DELETE /v1/tenants/{tenant_id}` -- operator removes a tenant.
///
/// Signed entries from this tenant stay in the DB (the signatures are still
/// cryptographically valid), but the materialized route table stops
/// surfacing them because the tenant is dropped from the in-memory
/// `OwnershipPolicy`. The removal is recorded in `tenant_removals` so hub
/// restart still skips the tenant when rebuilding the policy.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}",
    tag = "operator",
    params(("id" = String, Path, description = "Tenant id")),
    responses(
        (status = 200, description = "Tenant removed from the active routing policy"),
        (status = 400, description = "Invalid tenant id"),
    ),
    security(("operator_key" = [])),
)]
pub(super) async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    // Serialize the remove+policy_update against concurrent invite creation
    // so a tenant being deleted here can't be lost from a snapshot that
    // already includes a newly-created tenant.
    let _guard = state.invite_lock.lock().await;
    if let Err(e) = state.db.remove_tenant(&tenant_id, now_ms()).await {
        warn!(error = %e, "failed to persist tenant removal");
        return internal_error();
    }

    state.policy_update(|p| p.remove(&tenant_id));

    remove_tenant_from_port_index(&state, &tenant_id);
    trigger_route_rebuild(&state);

    json_ok(serde_json::json!({
        "status": "removed",
        "tenant_id": tenant_id.to_string(),
    }))
}
