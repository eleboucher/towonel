use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::DEFAULT_REGION;
use towonel_common::identity::TenantId;
use towonel_common::time::now_ms;
use tracing::warn;
use utoipa::ToSchema;

use crate::hub::auth::middleware::Principal;
use crate::hub::db::app_settings::{DEFAULT_USER_PORT_QUOTA, USER_PORT_QUOTA_KEY};
use crate::hub::db::port_reservations::{NewPortReservation, PortProtocol, PortReservationRow};

use super::{
    AppState, Pagination, conflict, error_response, internal_error, invalid_request, json_ok,
    json_ok_paged, json_with_status, not_found, paginate,
};

const MIN_RESERVABLE_PORT: u16 = 1024;

const HUB_RESERVED_PORTS: &[u16] = &[4443, 8443, 51820];

const AUTO_PICK_START: u16 = 10_000;
const AUTO_PICK_END: u16 = 32_767;

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ReservePortRequest {
    /// `tcp` or `udp`.
    protocol: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    preferred: Option<u16>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct EdgeInfo {
    node_id: String,
    addresses: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[utoipa::path(
    post,
    path = "/v1/tenants/{id}/ports",
    tag = "ports",
    params(("id" = String, Path, description = "Tenant id")),
    request_body = ReservePortRequest,
    responses(
        (status = 201, description = "Port reserved", body = ReservePortResponse),
        (status = 400, description = "Invalid tenant id, protocol, or port"),
        (status = 403, description = "Not authorized for this tenant, or quota exceeded"),
        (status = 409, description = "Port already in use / pool exhausted"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn post_port(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    axum::Json(mut req): axum::Json<ReservePortRequest>,
) -> Response {
    // Stored ip_address must string-match edge public_ips.
    req.ip = req.ip.map(|s| crate::config::canonical_ip(&s));
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

    let allowed = match allowed_regions_for_tenant(&state, &tenant_id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (selected_ip, port) = match select_ip_and_port(&state, &req, protocol, &allowed).await {
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
        Ok(_) => json_with_status(
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
        ),
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

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}/ports",
    tag = "ports",
    params(
        ("id" = String, Path, description = "Tenant id"),
        ("limit" = Option<usize>, Query, description = "Page size; omit to return all"),
        ("offset" = Option<usize>, Query, description = "Page offset (default 0)"),
    ),
    responses(
        (status = 200, description = "Port reservations for the tenant; total in X-Total-Count"),
        (status = 400, description = "Invalid tenant id"),
        (status = 403, description = "Not authorized for this tenant"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn list_ports(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    Query(page): Query<Pagination>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };
    if let Err(resp) = authorize_tenant(&state, &principal, &tenant_id).await {
        return resp;
    }
    match state.db.list_port_reservations(Some(&tenant_id)).await {
        Ok(rows) => {
            let ports: Vec<PortRow> = rows.into_iter().map(PortRow::from).collect();
            let (ports, total) = paginate(ports, &page);
            json_ok_paged(serde_json::json!({ "ports": ports }), total)
        }
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/ports",
    tag = "operator",
    params(
        ("limit" = Option<usize>, Query, description = "Page size; omit to return all"),
        ("offset" = Option<usize>, Query, description = "Page offset (default 0)"),
    ),
    responses((status = 200, description = "All port reservations; total in X-Total-Count")),
    security(("operator_key" = [])),
)]
pub(super) async fn list_all_ports(
    State(state): State<Arc<AppState>>,
    Query(page): Query<Pagination>,
) -> Response {
    match state.db.list_port_reservations(None).await {
        Ok(rows) => {
            let ports: Vec<PortRowWithTenant> =
                rows.into_iter().map(PortRowWithTenant::from).collect();
            let (ports, total) = paginate(ports, &page);
            json_ok_paged(serde_json::json!({ "ports": ports }), total)
        }
        Err(e) => {
            warn!(error = %e, "list_port_reservations(None) failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}/ports/{proto}/{port}",
    tag = "ports",
    params(
        ("id" = String, Path, description = "Tenant id"),
        ("proto" = String, Path, description = "`tcp` or `udp`"),
        ("port" = u16, Path, description = "Reserved port number"),
    ),
    responses(
        (status = 200, description = "Reservation released"),
        (status = 400, description = "Invalid tenant id or protocol"),
        (status = 403, description = "Not authorized for this tenant"),
        (status = 404, description = "Reservation does not exist"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
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

    for r in &reservations {
        if let Err(e) = state
            .db
            .delete_port_reservation(&tenant_id, r.ip_address.as_deref(), port, protocol)
            .await
        {
            warn!(error = %e, "delete_port_reservation failed");
            return internal_error();
        }
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

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct AvailablePortsQuery {
    protocol: String,
    #[serde(default)]
    count: Option<u16>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AvailablePortsResponse {
    protocol: String,
    range_start: u16,
    range_end: u16,
    ports: Vec<u16>,
}

#[utoipa::path(
    get,
    path = "/v1/ports/available",
    tag = "ports",
    params(
        ("protocol" = String, Query, description = "`tcp` or `udp`"),
        ("count" = Option<u16>, Query, description = "How many free ports to return (1..=200, default 20)"),
    ),
    responses(
        (status = 200, description = "A page of free ports in the auto-pick range", body = AvailablePortsResponse),
        (status = 400, description = "Invalid protocol"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
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

async fn allowed_regions_for_tenant(
    state: &Arc<AppState>,
    tenant_id: &TenantId,
) -> Result<HashSet<String>, Response> {
    let invite = match state.db.find_invite_by_tenant(tenant_id).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            warn!(%tenant_id, "no invite found for tenant; using default region");
            return Ok(HashSet::from_iter([DEFAULT_REGION.to_string()]));
        }
        Err(e) => {
            warn!(error = %e, %tenant_id, "find_invite_by_tenant failed");
            return Err(internal_error());
        }
    };
    let mut regions = HashSet::new();
    regions.insert(invite.region.unwrap_or_else(|| DEFAULT_REGION.to_string()));
    for r in invite.failover_regions {
        regions.insert(r);
    }
    Ok(regions)
}

/// Build a map from each public IP to the region of the edge that
/// advertises it (or `None` for the hub's own edge IPs).
fn ip_region_map(state: &Arc<AppState>) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut seen = HashSet::new();
    for ip in &state.identity.edge_public_ips {
        seen.insert(ip.clone());
        out.push((ip.clone(), state.identity.edge_region.clone()));
    }
    for (_, _, _, public_ips, region) in state.live_edges.snapshot() {
        for ip in public_ips {
            if seen.insert(ip.clone()) {
                out.push((ip, region.clone()));
            }
        }
    }
    out
}

fn available_ips(state: &Arc<AppState>) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    for (ip, _) in &ip_region_map(state) {
        ips.push(ip.clone());
    }
    ips
}

/// Like [`available_ips`] but keeps only IPs whose edge region is in
/// `allowed_regions`.
fn available_ips_in_regions(state: &Arc<AppState>, allowed: &HashSet<String>) -> Vec<String> {
    ip_region_map(state)
        .into_iter()
        .filter(|(_, region)| {
            let r = region.as_deref().unwrap_or(DEFAULT_REGION);
            allowed.contains(r)
        })
        .map(|(ip, _)| ip)
        .collect()
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
    allowed_regions: &HashSet<String>,
) -> Result<(Option<String>, u16), Response> {
    let region_ips = available_ips_in_regions(state, allowed_regions);
    // Empty only when no edge anywhere advertises a public IP (single-node
    // setups); a down region must not degrade into out-of-region IPs.
    let any_ips = !available_ips(state).is_empty();

    if let Some(ref ip) = req.ip {
        if any_ips && !region_ips.iter().any(|i| i == ip) {
            let available = if region_ips.len() < available_ips(state).len() {
                format!(
                    "{} (tenant's regions: {})",
                    region_ips.join(", "),
                    allowed_regions
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            } else {
                region_ips.join(", ")
            };
            return Err(invalid_request(format!(
                "ip {ip} is not served by any edge in the tenant's region; available: {available}",
            )));
        }
        let p = match req.preferred {
            Some(p) => p,
            None => pick_free_port_for_ip(state, protocol, Some(ip), allowed_regions).await?,
        };
        return Ok((Some(ip.clone()), p));
    }
    match req.preferred {
        Some(p) => {
            let ip = pick_ip_for_port(state, protocol, p, allowed_regions).await?;
            Ok((Some(ip), p))
        }
        None => pick_ip_and_port(state, protocol, allowed_regions).await,
    }
}

/// Fetch all port reservations, mapping a DB error to a 500 response. `ctx`
/// names the calling operation for the log line.
async fn load_reservations(
    state: &Arc<AppState>,
    ctx: &str,
) -> Result<Vec<PortReservationRow>, Response> {
    state.db.list_port_reservations(None).await.map_err(|e| {
        warn!(error = %e, "list_port_reservations failed during {ctx}");
        internal_error()
    })
}

/// Ports already reserved for `protocol` on `ip` (`None` = the shared,
/// IP-less pool).
fn used_ports(
    rows: &[PortReservationRow],
    protocol: PortProtocol,
    ip: Option<&str>,
) -> std::collections::HashSet<u16> {
    rows.iter()
        .filter(|r| r.protocol == protocol && r.ip_address.as_deref() == ip)
        .map(|r| r.port)
        .collect()
}

/// First port in the auto-pick range that is neither `used` nor hub-reserved.
fn first_free_port(used: &std::collections::HashSet<u16>) -> Option<u16> {
    (AUTO_PICK_START..=AUTO_PICK_END).find(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
}

async fn pick_ip_and_port(
    state: &Arc<AppState>,
    protocol: PortProtocol,
    allowed_regions: &HashSet<String>,
) -> Result<(Option<String>, u16), Response> {
    let ips = available_ips_in_regions(state, allowed_regions);
    let existing = load_reservations(state, "auto-pick").await?;

    if ips.is_empty() {
        // The IP-less pool is for single-node setups with no public IPs
        // anywhere. With IPs elsewhere but none in-region, fail instead —
        // an IP-less reservation would be served by every region's edges.
        if !available_ips(state).is_empty() {
            return Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_assignable_ip",
                format!(
                    "no edge in the tenant's region currently advertises a public IP \
                     to assign for {}; retry once the region's edge is back",
                    protocol.as_str()
                ),
            ));
        }
        let port = first_free_port(&used_ports(&existing, protocol, None)).ok_or_else(|| {
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
        if let Some(port) = first_free_port(&used_ports(&existing, protocol, Some(ip))) {
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

/// Auto-assign a concrete IP for a user-chosen `port`: the first available
/// edge IP on which the port is still free. Fails if no edge advertises a
/// public IP (nothing to assign) or the port is taken on every IP.
async fn pick_ip_for_port(
    state: &Arc<AppState>,
    protocol: PortProtocol,
    port: u16,
    allowed_regions: &HashSet<String>,
) -> Result<String, Response> {
    let ips = available_ips_in_regions(state, allowed_regions);
    if ips.is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_assignable_ip",
            format!(
                "no edge advertises a public IP to assign for {} port {port}; \
                 connect an edge with a public IP and retry",
                protocol.as_str()
            ),
        ));
    }

    let existing = load_reservations(state, "ip-for-port pick").await?;
    for ip in &ips {
        let taken = existing.iter().any(|r| {
            r.protocol == protocol && r.port == port && r.ip_address.as_deref() == Some(ip.as_str())
        });
        if !taken {
            return Ok(ip.clone());
        }
    }

    Err(conflict(
        "port_in_use",
        format!(
            "{} port {port} is already reserved on all available IPs in the tenant's region",
            protocol.as_str()
        ),
    ))
}

async fn pick_free_port_for_ip(
    state: &Arc<AppState>,
    protocol: PortProtocol,
    ip: Option<&str>,
    allowed_regions: &HashSet<String>,
) -> Result<u16, Response> {
    // Validate that the IP (if specified) is in an allowed region.
    if let Some(ip) = ip {
        let region_ips = available_ips_in_regions(state, allowed_regions);
        if !region_ips.is_empty() && !region_ips.iter().any(|i| i == ip) {
            return Err(invalid_request(format!(
                "ip {ip} is not served by any edge in the tenant's region"
            )));
        }
    }
    let existing = load_reservations(state, "auto-pick for ip").await?;
    first_free_port(&used_ports(&existing, protocol, ip)).ok_or_else(|| {
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
