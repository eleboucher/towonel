use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::edge_link::PortReservationEntry;
use towonel_common::identity::TenantId;
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::auth::middleware::Principal;
use crate::hub::db::app_settings::{DEFAULT_USER_PORT_QUOTA, USER_PORT_QUOTA_KEY};
use crate::hub::db::port_reservations::{NewPortReservation, PortProtocol, PortReservationRow};
use crate::hub::edge_link::PortReservationDelta;

use super::{
    AppState, conflict, error_response, internal_error, invalid_request, json_ok, json_with_status,
    not_found,
};

const MIN_RESERVABLE_PORT: u16 = 1024;

const HUB_RESERVED_PORTS: &[u16] = &[4443, 8443, 51820];

const AUTO_PICK_START: u16 = 10_000;
const AUTO_PICK_END: u16 = 32_767;

#[derive(Debug, Deserialize)]
pub(super) struct ReservePortRequest {
    protocol: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    preferred: Option<u16>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct EdgeInfo {
    node_id: String,
    addresses: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReservePortResponse {
    status: &'static str,
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
    claimed_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge: Option<EdgeInfo>,
}

#[derive(Debug, Serialize)]
struct PortRow {
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
    claimed_at_ms: u64,
}

impl From<PortReservationRow> for PortRow {
    fn from(row: PortReservationRow) -> Self {
        Self {
            port: row.port,
            protocol: row.protocol.as_str().to_string(),
            ip: row.ip_address,
            label: row.label,
            claimed_at_ms: row.claimed_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct PortRowWithTenant {
    tenant_id: String,
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
    claimed_at_ms: u64,
}

impl From<PortReservationRow> for PortRowWithTenant {
    fn from(row: PortReservationRow) -> Self {
        Self {
            tenant_id: row.tenant_id.to_string(),
            port: row.port,
            protocol: row.protocol.as_str().to_string(),
            ip: row.ip_address,
            label: row.label,
            claimed_at_ms: row.claimed_at_ms,
        }
    }
}

pub(super) async fn post_port(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    axum::Json(req): axum::Json<ReservePortRequest>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    let owner_user_id = match authorize_tenant(&state, &principal, &tenant_id).await {
        Ok(uid) => uid,
        Err(resp) => return resp,
    };

    let Some(protocol) = PortProtocol::parse(&req.protocol) else {
        return invalid_request("protocol must be \"tcp\" or \"udp\"");
    };

    if let Some(p) = req.preferred
        && let Err(msg) = validate_port_allowed(p)
    {
        return invalid_request(msg);
    }

    let (_tcp_guard, _udp_guard) = if owner_user_id.is_some() {
        (
            Some(state.tcp_port_lock.lock().await),
            Some(state.udp_port_lock.lock().await),
        )
    } else {
        match protocol {
            PortProtocol::Tcp => (Some(state.tcp_port_lock.lock().await), None),
            PortProtocol::Udp => (None, Some(state.udp_port_lock.lock().await)),
        }
    };

    if let Some(user_id) = owner_user_id.as_deref()
        && let Err(resp) = enforce_user_port_quota(&state, user_id).await
    {
        return resp;
    }

    let (selected_ip, port) = match select_ip_and_port(&state, &req, protocol).await {
        Ok(result) => result,
        Err(resp) => return resp,
    };

    let label = req.label;
    let claimed_at_ms = now_ms();
    let row = NewPortReservation {
        tenant_id,
        ip_address: selected_ip.as_deref(),
        port,
        protocol,
        label: label.as_deref(),
        claimed_at_ms,
    };
    let edge = find_edge_for_ip(&state, selected_ip.as_deref());
    match state.db.insert_port_reservation(&row).await {
        Ok(_) => {
            broadcast_delta(
                &state,
                vec![PortReservationEntry {
                    tenant_id,
                    ip: selected_ip.clone(),
                    port,
                    protocol: protocol.as_str().to_string(),
                }],
                vec![],
            );
            json_with_status(
                StatusCode::CREATED,
                ReservePortResponse {
                    status: "ok",
                    port,
                    protocol: protocol.as_str().to_string(),
                    ip: selected_ip,
                    label,
                    claimed_at_ms,
                    edge,
                },
            )
        }
        Err(e) if crate::hub::db::is_unique_violation(&e) => conflict(
            "port_in_use",
            format!("{} port {port} is already reserved", protocol.as_str()),
        ),
        Err(e) => {
            warn!(error = %e, "insert_port_reservation failed");
            internal_error()
        }
    }
}

fn broadcast_delta(
    state: &Arc<AppState>,
    added: Vec<PortReservationEntry>,
    removed: Vec<PortReservationEntry>,
) {
    if state.port_reservations_tx.receiver_count() == 0 {
        return;
    }
    if state
        .port_reservations_tx
        .send(PortReservationDelta { added, removed })
        .is_err()
    {
        tracing::debug!("port reservation delta: no subscribers");
    }
}

pub(super) async fn list_ports(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };
    if let Err(resp) = authorize_tenant(&state, &principal, &tenant_id).await {
        return resp;
    }
    match state.db.list_port_reservations(Some(&tenant_id)).await {
        Ok(rows) => json_ok(serde_json::json!({
            "ports": rows.into_iter().map(PortRow::from).collect::<Vec<_>>(),
        })),
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed");
            internal_error()
        }
    }
}

pub(super) async fn list_all_ports(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_port_reservations(None).await {
        Ok(rows) => json_ok(serde_json::json!({
            "ports": rows.into_iter().map(PortRowWithTenant::from).collect::<Vec<_>>(),
        })),
        Err(e) => {
            warn!(error = %e, "list_port_reservations(None) failed");
            internal_error()
        }
    }
}

pub(super) async fn delete_port(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path((id, proto_str, port)): Path<(String, String, u16)>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };
    if let Err(resp) = authorize_tenant(&state, &principal, &tenant_id).await {
        return resp;
    }
    let Some(protocol) = PortProtocol::parse(&proto_str) else {
        return invalid_request("protocol must be \"tcp\" or \"udp\"");
    };

    let reservations = match state
        .db
        .find_port_reservations(&tenant_id, port, protocol)
        .await
    {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) => return not_found("port reservation does not exist"),
        Err(e) => {
            warn!(error = %e, "find_port_reservations failed");
            return internal_error();
        }
    };

    let mut released = 0;
    for r in &reservations {
        match state
            .db
            .delete_port_reservation(&tenant_id, r.ip_address.as_deref(), port, protocol)
            .await
        {
            Ok(true) => released += 1,
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "delete_port_reservation failed");
                return internal_error();
            }
        }
    }

    if released > 0 {
        broadcast_delta(
            &state,
            vec![],
            reservations
                .into_iter()
                .map(|r| PortReservationEntry {
                    tenant_id,
                    ip: r.ip_address,
                    port,
                    protocol: protocol.as_str().to_string(),
                })
                .collect(),
        );
    }
    json_ok(serde_json::json!({"status": "released"}))
}

/// `Ok(None)` for operator principals (skip the quota check at the call site).
/// `Ok(Some(user_id))` for users who own the tenant. 403 otherwise.
async fn authorize_tenant(
    state: &Arc<AppState>,
    principal: &Principal,
    tenant_id: &TenantId,
) -> Result<Option<String>, Response> {
    if principal.is_operator() {
        return Ok(None);
    }
    let Principal::User(user) = principal else {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "not authorized for this tenant",
        ));
    };
    match state
        .db
        .find_tenant_ownership(&user.id, tenant_id.as_bytes())
        .await
    {
        Ok(Some(_)) => Ok(Some(user.id.clone())),
        Ok(None) => Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "not authorized for this tenant",
        )),
        Err(e) => {
            warn!(error = %e, "find_tenant_ownership failed");
            Err(internal_error())
        }
    }
}

async fn enforce_user_port_quota(state: &Arc<AppState>, user_id: &str) -> Result<(), Response> {
    let quota = match state.db.get_setting_int(USER_PORT_QUOTA_KEY).await {
        Ok(Some(v)) => v,
        Ok(None) => DEFAULT_USER_PORT_QUOTA,
        Err(e) => {
            warn!(error = %e, "get_setting_int user_port_quota failed");
            return Err(internal_error());
        }
    };
    let used = match state.db.count_port_reservations_for_user(user_id).await {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "count_port_reservations_for_user failed");
            return Err(internal_error());
        }
    };
    if used >= quota {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "port_quota_exceeded",
            format!("user already holds {used} of {quota} allowed port reservations"),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(super) struct AvailablePortsQuery {
    protocol: String,
    #[serde(default)]
    count: Option<u16>,
}

#[derive(Debug, Serialize)]
struct AvailablePortsResponse {
    protocol: String,
    range_start: u16,
    range_end: u16,
    ports: Vec<u16>,
}

pub(super) async fn get_available_ports(
    State(state): State<Arc<AppState>>,
    _principal: Principal,
    Query(q): Query<AvailablePortsQuery>,
) -> Response {
    let Some(protocol) = PortProtocol::parse(&q.protocol) else {
        return invalid_request("protocol must be \"tcp\" or \"udp\"");
    };
    let count = q.count.unwrap_or(20).clamp(1, 200);

    let existing = match state.db.list_port_reservations(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed in get_available_ports");
            return internal_error();
        }
    };
    let ips = available_ips(&state);
    let used: std::collections::HashSet<u16> = if ips.is_empty() {
        existing
            .into_iter()
            .filter(|r| r.protocol == protocol && r.ip_address.is_none())
            .map(|r| r.port)
            .collect()
    } else {
        existing
            .into_iter()
            .filter(|r| {
                r.protocol == protocol
                    && r.ip_address
                        .as_deref()
                        .is_some_and(|ip| ips.iter().any(|i| i == ip))
            })
            .map(|r| r.port)
            .collect()
    };

    let ports: Vec<u16> = (AUTO_PICK_START..=AUTO_PICK_END)
        .filter(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
        .take(count as usize)
        .collect();

    json_ok(AvailablePortsResponse {
        protocol: protocol.as_str().to_string(),
        range_start: AUTO_PICK_START,
        range_end: AUTO_PICK_END,
        ports,
    })
}

fn validate_port_allowed(port: u16) -> Result<(), String> {
    if port < MIN_RESERVABLE_PORT {
        return Err(format!(
            "port {port} is below the reservable floor ({MIN_RESERVABLE_PORT})"
        ));
    }
    if HUB_RESERVED_PORTS.contains(&port) {
        return Err(format!("port {port} is reserved by the hub/edge"));
    }
    Ok(())
}

fn available_ips(state: &Arc<AppState>) -> Vec<String> {
    let mut ips = state.identity.edge_public_ips.clone();
    for (_, _, _, public_ips, _) in state.live_edges.snapshot() {
        for ip in public_ips {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

fn find_edge_for_ip(state: &Arc<AppState>, ip: Option<&str>) -> Option<EdgeInfo> {
    let ip = ip?;
    if let (Some(node_id), true) = (
        state.identity.edge_node_id,
        state.identity.edge_public_ips.iter().any(|i| i == ip),
    ) {
        return Some(EdgeInfo {
            node_id: node_id.to_string(),
            addresses: state.identity.edge_iroh_addresses.clone(),
        });
    }
    for (edge_id, iroh_endpoints, _, public_ips, _) in state.live_edges.snapshot() {
        if public_ips.iter().any(|i| i == ip)
            && let Ok(node_id) = iroh::EndpointId::from_bytes(&edge_id)
        {
            return Some(EdgeInfo {
                node_id: node_id.to_string(),
                addresses: iroh_endpoints,
            });
        }
    }
    None
}

async fn select_ip_and_port(
    state: &Arc<AppState>,
    req: &ReservePortRequest,
    protocol: PortProtocol,
) -> Result<(Option<String>, u16), Response> {
    if let Some(ref ip) = req.ip {
        let ips = available_ips(state);
        if !ips.is_empty() && !ips.iter().any(|i| i == ip) {
            return Err(invalid_request(format!(
                "ip {ip} is not served by any connected edge; available: {}",
                ips.join(", ")
            )));
        }
        let p = match req.preferred {
            Some(p) => p,
            None => pick_free_port_for_ip(state, protocol, Some(ip)).await?,
        };
        return Ok((Some(ip.clone()), p));
    }
    match req.preferred {
        Some(p) => {
            let ip = pick_ip_for_port(state, protocol, p).await?;
            Ok((ip, p))
        }
        None => pick_ip_and_port(state, protocol).await,
    }
}

async fn pick_ip_and_port(
    state: &Arc<AppState>,
    protocol: PortProtocol,
) -> Result<(Option<String>, u16), Response> {
    let ips = available_ips(state);
    let existing = match state.db.list_port_reservations(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed during auto-pick");
            return Err(internal_error());
        }
    };

    if ips.is_empty() {
        let used: std::collections::HashSet<u16> = existing
            .into_iter()
            .filter(|r| r.protocol == protocol && r.ip_address.is_none())
            .map(|r| r.port)
            .collect();
        let port = (AUTO_PICK_START..=AUTO_PICK_END)
            .find(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
            .ok_or_else(|| {
                conflict(
                    "port_pool_exhausted",
                    format!(
                        "no free {} port in {AUTO_PICK_START}..={AUTO_PICK_END}",
                        protocol.as_str()
                    ),
                )
            })?;
        return Ok((None, port));
    }

    for ip in &ips {
        let used: std::collections::HashSet<u16> = existing
            .iter()
            .filter(|r| r.protocol == protocol && r.ip_address.as_deref() == Some(ip.as_str()))
            .map(|r| r.port)
            .collect();
        if let Some(port) = (AUTO_PICK_START..=AUTO_PICK_END)
            .find(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
        {
            return Ok((Some(ip.clone()), port));
        }
    }

    Err(conflict(
        "port_pool_exhausted",
        format!(
            "no free {} port in {AUTO_PICK_START}..={AUTO_PICK_END} on any available IP",
            protocol.as_str()
        ),
    ))
}

async fn pick_ip_for_port(
    state: &Arc<AppState>,
    protocol: PortProtocol,
    port: u16,
) -> Result<Option<String>, Response> {
    let ips = available_ips(state);
    let existing = match state.db.list_port_reservations(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed during ip-for-port pick");
            return Err(internal_error());
        }
    };

    if ips.is_empty() {
        let taken = existing
            .iter()
            .any(|r| r.protocol == protocol && r.port == port && r.ip_address.is_none());
        if !taken {
            return Ok(None);
        }
        return Err(conflict(
            "port_in_use",
            format!("{} port {port} is already reserved", protocol.as_str()),
        ));
    }

    for ip in &ips {
        let taken = existing.iter().any(|r| {
            r.protocol == protocol && r.port == port && r.ip_address.as_deref() == Some(ip.as_str())
        });
        if !taken {
            return Ok(Some(ip.clone()));
        }
    }

    Err(conflict(
        "port_in_use",
        format!(
            "{} port {port} is already reserved on all available IPs",
            protocol.as_str()
        ),
    ))
}

async fn pick_free_port_for_ip(
    state: &Arc<AppState>,
    protocol: PortProtocol,
    ip: Option<&str>,
) -> Result<u16, Response> {
    let existing = match state.db.list_port_reservations(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed during auto-pick for ip");
            return Err(internal_error());
        }
    };
    let used: std::collections::HashSet<u16> = existing
        .into_iter()
        .filter(|r| r.protocol == protocol && r.ip_address.as_deref() == ip)
        .map(|r| r.port)
        .collect();

    (AUTO_PICK_START..=AUTO_PICK_END)
        .find(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
        .ok_or_else(|| {
            let ip_label = ip.unwrap_or("shared");
            conflict(
                "port_pool_exhausted",
                format!(
                    "no free {} port in {AUTO_PICK_START}..={AUTO_PICK_END} on {ip_label}",
                    protocol.as_str()
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_blocks_floor() {
        assert!(validate_port_allowed(1023).is_err());
        assert!(validate_port_allowed(80).is_err());
    }

    #[test]
    fn validate_blocks_hub_ports() {
        assert!(validate_port_allowed(4443).is_err());
        assert!(validate_port_allowed(8443).is_err());
        assert!(validate_port_allowed(51820).is_err());
    }

    #[test]
    fn validate_allows_normal_port() {
        validate_port_allowed(22000).unwrap();
        validate_port_allowed(9000).unwrap();
    }
}
