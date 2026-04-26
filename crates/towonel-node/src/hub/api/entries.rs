use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use serde::Serialize;
use towonel_common::config_entry::{ConfigEntryError, ConfigOp, ConfigPayload, SignedConfigEntry};
use towonel_common::identity::TenantId;
use tracing::warn;

use towonel_common::time::now_ms;

use super::super::metrics::reject_reason;
use super::{
    AppState, PROTOCOL_VERSION, cbor_response, hostname_not_owned, internal_error, invalid_request,
    invalid_signature, json_ok, load_trusted_edges, rebuild_and_broadcast_routes,
    sequence_conflict, tenant_not_allowed, unsupported_op, unsupported_version,
};

#[derive(Serialize)]
struct PostEntryResponse {
    status: &'static str,
    sequence: u64,
}

/// Service names are operator-chosen opaque labels — only reject what would
/// break wire format or logs.
fn validate_tcp_service_name(name: &str) -> Result<(), &'static str> {
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

fn validate_tcp_listen_port(port: u16) -> Result<(), &'static str> {
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

/// Replay all stored entries to find whether `listen_port` is already claimed.
/// Skips ML-DSA re-verification — entries in the DB were already verified at
/// insert time, and re-checking on every `UpsertTcpService` was O(N×crypto)
/// under the global `tcp_port_lock`.
///
/// `policy` still gates the scan: entries from removed tenants are ignored,
/// matching the behavior of `RouteTable::from_entries`.
async fn find_port_conflict(
    db: &super::super::db::Db,
    listen_port: u16,
    requesting_tenant: &TenantId,
    requesting_service: &str,
    policy: &towonel_common::ownership::OwnershipPolicy,
) -> Option<PortConflict> {
    let entries = db.get_all_entries().await.ok()?;
    let mut per_tenant: std::collections::HashMap<
        TenantId,
        std::collections::HashMap<String, u16>,
    > = std::collections::HashMap::new();
    for entry in &entries {
        if policy.pq_public_key(&entry.tenant_id).is_none() {
            continue;
        }
        let Ok(payload) = entry.payload_unverified() else {
            continue;
        };
        let map = per_tenant.entry(payload.tenant_id).or_default();
        match payload.op {
            ConfigOp::UpsertTcpService {
                service,
                listen_port: port,
            } => {
                map.insert(service, port);
            }
            ConfigOp::DeleteTcpService { service } => {
                map.remove(&service);
            }
            _ => {}
        }
    }
    for (tenant_id, bindings) in &per_tenant {
        for (service, port) in bindings {
            if *port != listen_port {
                continue;
            }
            if tenant_id != requesting_tenant {
                return Some(PortConflict::OtherTenant { tenant: *tenant_id });
            }
            if service != requesting_service {
                return Some(PortConflict::SameTenantOtherService {
                    service: service.clone(),
                });
            }
        }
    }
    None
}

async fn validate_tcp_service_op(
    state: &Arc<AppState>,
    payload: &ConfigPayload,
) -> Result<(), Response> {
    let service_name = match &payload.op {
        ConfigOp::UpsertTcpService { service, .. } | ConfigOp::DeleteTcpService { service } => {
            Some(service)
        }
        _ => None,
    };
    if let Some(service) = service_name
        && let Err(e) = validate_tcp_service_name(service)
    {
        state
            .metrics
            .record_reject(reject_reason::INVALID_TCP_SERVICE);
        return Err(invalid_request(format!(
            "invalid tcp service name `{service}`: {e}"
        )));
    }

    if let ConfigOp::UpsertTcpService {
        service,
        listen_port,
    } = &payload.op
    {
        if let Err(e) = validate_tcp_listen_port(*listen_port) {
            state.metrics.record_reject(reject_reason::INVALID_TCP_PORT);
            return Err(invalid_request(format!(
                "invalid tcp listen_port {listen_port}: {e}"
            )));
        }
        match find_port_conflict(
            &state.db,
            *listen_port,
            &payload.tenant_id,
            service,
            state.policy.load().as_ref(),
        )
        .await
        {
            None => {}
            Some(PortConflict::OtherTenant { tenant }) => {
                state.metrics.record_reject(reject_reason::TCP_PORT_CLAIMED);
                return Err(invalid_request(format!(
                    "tcp listen_port {listen_port} is already claimed by tenant {tenant}"
                )));
            }
            Some(PortConflict::SameTenantOtherService {
                service: other_service,
            }) => {
                state.metrics.record_reject(reject_reason::TCP_PORT_CLAIMED);
                return Err(invalid_request(format!(
                    "tcp listen_port {listen_port} is already bound to service `{other_service}` for this tenant"
                )));
            }
        }
    }
    Ok(())
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

    if payload.version != PROTOCOL_VERSION {
        state
            .metrics
            .record_reject(reject_reason::UNSUPPORTED_VERSION);
        return unsupported_version(format!(
            "payload version {} is not supported by this hub (expected {PROTOCOL_VERSION})",
            payload.version
        ));
    }

    let hostname_for_check = match &payload.op {
        ConfigOp::UpsertHostname { hostname }
        | ConfigOp::DeleteHostname { hostname }
        | ConfigOp::SetHostnameTls { hostname, .. } => Some(hostname),
        ConfigOp::UpsertAgent { .. }
        | ConfigOp::RevokeAgent { .. }
        | ConfigOp::UpsertTcpService { .. }
        | ConfigOp::DeleteTcpService { .. } => None,
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

    // Serialize cross-tenant uniqueness check + insert for TCP-service ops.
    let _tcp_guard = if matches!(payload.op, ConfigOp::UpsertTcpService { .. }) {
        Some(state.tcp_port_lock.lock().await)
    } else {
        None
    };

    if let Err(resp) = validate_tcp_service_op(&state, &payload).await {
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

    if let Err(e) = rebuild_and_broadcast_routes(&state).await {
        warn!(error = %e, "failed to rebuild routes after insert");
    }

    cbor_response(&PostEntryResponse {
        status: "ok",
        sequence,
    })
}

pub(super) async fn get_tenant_entries(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

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

pub(super) async fn list_edges(State(state): State<Arc<AppState>>) -> Response {
    #[derive(Serialize)]
    struct EdgeEntry<'a> {
        node_id: iroh::EndpointId,
        addresses: &'a [String],
    }
    #[derive(Serialize)]
    struct ListEdgesResponse<'a> {
        edges: Vec<EdgeEntry<'a>>,
    }

    let mut node_ids = match load_trusted_edges(&state).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "failed to list edges");
            return internal_error();
        }
    };
    if let Some(self_edge) = state.identity.edge_node_id
        && !node_ids.contains(&self_edge)
    {
        node_ids.push(self_edge);
    }

    let empty: &[String] = &[];
    let edges = node_ids
        .into_iter()
        .map(|node_id| {
            let addresses = if state.identity.edge_node_id == Some(node_id) {
                state.identity.edge_addresses.as_slice()
            } else {
                empty
            };
            EdgeEntry { node_id, addresses }
        })
        .collect();

    json_ok(ListEdgesResponse { edges })
}

/// `DELETE /v1/tenants/{tenant_id}` -- operator removes a tenant.
///
/// Signed entries from this tenant stay in the DB (the signatures are still
/// cryptographically valid), but the materialized route table stops
/// surfacing them because the tenant is dropped from the in-memory
/// `OwnershipPolicy`. The removal is recorded in `tenant_removals` so hub
/// restart still skips the tenant when rebuilding the policy.
pub(super) async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    if let Err(e) = state.db.remove_tenant(&tenant_id, now_ms()).await {
        warn!(error = %e, "failed to persist tenant removal");
        return internal_error();
    }

    state.policy_update(|p| p.remove(&tenant_id));

    if let Err(e) = rebuild_and_broadcast_routes(&state).await {
        warn!(error = %e, "failed to rebuild routes after tenant removal");
    }

    json_ok(serde_json::json!({
        "status": "removed",
        "tenant_id": tenant_id.to_string(),
    }))
}
