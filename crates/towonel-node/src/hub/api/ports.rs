use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use towonel_common::edge_link::PortReservationEntry;
use towonel_common::identity::TenantId;
use towonel_common::time::now_ms;
use tracing::warn;

use crate::hub::db::port_reservations::{NewPortReservation, PortProtocol, PortReservationRow};
use crate::hub::edge_link::PortReservationDelta;

use super::{
    AppState, conflict, internal_error, invalid_request, json_ok, json_with_status, not_found,
};

const MIN_RESERVABLE_PORT: u16 = 1024;

// Bound to the hub/edge itself; can't be handed to a tenant.
const HUB_RESERVED_PORTS: &[u16] = &[4443, 8443, 51820];

// Sits above ip_local_port_range (default 32768..=60999) so auto-picked
// ports don't collide with the kernel's outbound ephemeral range.
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
struct ReservePortResponse {
    status: &'static str,
    port: u16,
    protocol: String,
    ip: Option<String>,
    label: Option<String>,
    claimed_at_ms: u64,
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
    Path(id): Path<String>,
    axum::Json(req): axum::Json<ReservePortRequest>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };

    let Some(protocol) = PortProtocol::parse(&req.protocol) else {
        return invalid_request("protocol must be \"tcp\" or \"udp\"");
    };

    if req.ip.is_some() {
        return invalid_request(
            "reserving a port on a specific IP is not yet supported; \
             omit `ip` to reserve on the shared IP",
        );
    }

    if let Some(p) = req.preferred
        && let Err(msg) = validate_port_allowed(p)
    {
        return invalid_request(msg);
    }

    // Serializes the check-then-insert window so a concurrent auto-pick
    // can't land on the same port.
    let _guard = match protocol {
        PortProtocol::Tcp => state.tcp_port_lock.lock().await,
        PortProtocol::Udp => state.udp_port_lock.lock().await,
    };

    let port = match req.preferred {
        Some(p) => p,
        None => match pick_free_port(&state, protocol).await {
            Ok(p) => p,
            Err(resp) => return resp,
        },
    };

    let label = req.label;
    let claimed_at_ms = now_ms();
    let row = NewPortReservation {
        tenant_id,
        ip_address: None,
        port,
        protocol,
        label: label.as_deref(),
        claimed_at_ms,
    };
    match state.db.insert_port_reservation(&row).await {
        Ok(_) => {
            broadcast_delta(
                &state,
                vec![PortReservationEntry {
                    tenant_id,
                    ip: None,
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
                    ip: None,
                    label,
                    claimed_at_ms,
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
    Path(id): Path<String>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };
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
    Path((id, proto_str, port)): Path<(String, String, u16)>,
) -> Response {
    let tenant_id: TenantId = match id.parse() {
        Ok(t) => t,
        Err(e) => return invalid_request(format!("invalid tenant_id: {e}")),
    };
    let Some(protocol) = PortProtocol::parse(&proto_str) else {
        return invalid_request("protocol must be \"tcp\" or \"udp\"");
    };

    match state
        .db
        .delete_port_reservation(&tenant_id, None, port, protocol)
        .await
    {
        Ok(true) => {
            broadcast_delta(
                &state,
                vec![],
                vec![PortReservationEntry {
                    tenant_id,
                    ip: None,
                    port,
                    protocol: protocol.as_str().to_string(),
                }],
            );
            json_ok(serde_json::json!({"status": "released"}))
        }
        Ok(false) => not_found("port reservation does not exist"),
        Err(e) => {
            warn!(error = %e, "delete_port_reservation failed");
            internal_error()
        }
    }
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

async fn pick_free_port(state: &Arc<AppState>, protocol: PortProtocol) -> Result<u16, Response> {
    let existing = match state.db.list_port_reservations(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "list_port_reservations failed during auto-pick");
            return Err(internal_error());
        }
    };
    let used: std::collections::HashSet<u16> = existing
        .into_iter()
        .filter(|r| r.protocol == protocol && r.ip_address.is_none())
        .map(|r| r.port)
        .collect();

    (AUTO_PICK_START..=AUTO_PICK_END)
        .find(|p| !used.contains(p) && !HUB_RESERVED_PORTS.contains(p))
        .ok_or_else(|| {
            conflict(
                "port_pool_exhausted",
                format!(
                    "no free {} port in {AUTO_PICK_START}..={AUTO_PICK_END}",
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
