use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::{AgentId, PQ_PUB_KEY_LEN, TenantId};
use crate::routing::RouteTable;

pub const EDGE_LINK_VERSION: u16 = 2;

pub const EDGE_LINK_MAX_FRAME: usize = 16 * 1024 * 1024;

pub type Kid = crate::edge_cred::Kid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubSigningKey {
    pub kid: Kid,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

impl HubSigningKey {
    pub fn new(kid: Kid, public_key: Vec<u8>) -> anyhow::Result<Self> {
        if public_key.len() != PQ_PUB_KEY_LEN {
            anyhow::bail!(
                "hub signing key wrong length: got {}, want {PQ_PUB_KEY_LEN}",
                public_key.len()
            );
        }
        Ok(Self { kid, public_key })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeToHub {
    /// Must be the first frame; the hub closes the link on PSK mismatch.
    Hello {
        edge_id: [u8; 32],
        iroh_endpoints: Vec<String>,
        software_version: String,
        #[serde(with = "serde_bytes")]
        psk: [u8; 32],
    },
    SessionAdded {
        agent_id: AgentId,
        tenant_id: TenantId,
    },
    SessionRemoved {
        agent_id: AgentId,
    },
    SessionsSnapshot {
        sessions: Vec<(AgentId, TenantId)>,
    },
    /// Opaque control frame the hub must verify and respond to.
    ControlRequest {
        request_id: u64,
        #[serde(with = "serde_bytes")]
        frame: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortReservationEntry {
    pub tenant_id: TenantId,
    pub ip: Option<String>,
    pub port: u16,
    pub protocol: String,
}

/// `RouteSnapshot.table` is boxed because `RouteTable` dwarfs every other
/// variant. No `PartialEq`/`Eq` — `RouteTable` carries `HashMap`/`HashSet`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HubToEdge {
    /// Sent in response to `Hello`.
    Welcome {
        hub_id: [u8; 32],
        signing_keys: Vec<HubSigningKey>,
    },
    RouteSnapshot {
        table: Box<RouteTable>,
    },
    KeyAdded(HubSigningKey),
    KeyRetired {
        kid: Kid,
    },
    PortReservationsSnapshot {
        entries: Vec<PortReservationEntry>,
    },
    PortReservationsChanged {
        added: Vec<PortReservationEntry>,
        removed: Vec<PortReservationEntry>,
    },
    /// Reply to `EdgeToHub::ControlRequest`. `status` uses the same byte
    /// codes as the tunnel control frames (see `towonel_common::tunnel`).
    ControlResponse {
        request_id: u64,
        status: u8,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EdgeLinkError {
    #[error("frame too large: {0} bytes exceeds {EDGE_LINK_MAX_FRAME}")]
    FrameTooLarge(usize),
    #[error("unknown frame version: {0} (this build speaks v{EDGE_LINK_VERSION})")]
    UnknownVersion(u16),
    #[error("frame too short to contain a version header")]
    Truncated,
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

async fn read_frame_bytes<R>(reader: &mut R) -> Result<Vec<u8>, EdgeLinkError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > EDGE_LINK_MAX_FRAME {
        return Err(EdgeLinkError::FrameTooLarge(len));
    }
    if len < 2 {
        return Err(EdgeLinkError::Truncated);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame_bytes<W>(writer: &mut W, payload: &[u8]) -> Result<(), EdgeLinkError>
where
    W: AsyncWrite + Unpin,
{
    let total = payload
        .len()
        .checked_add(2)
        .ok_or(EdgeLinkError::FrameTooLarge(usize::MAX))?;
    if total > EDGE_LINK_MAX_FRAME {
        return Err(EdgeLinkError::FrameTooLarge(total));
    }
    let len_u32 = u32::try_from(total).map_err(|_e| EdgeLinkError::FrameTooLarge(total))?;
    writer.write_u32(len_u32).await?;
    writer.write_u16(EDGE_LINK_VERSION).await?;
    writer.write_all(payload).await?;
    Ok(())
}

fn decode_versioned<T>(frame: &[u8]) -> Result<T, EdgeLinkError>
where
    T: for<'de> Deserialize<'de>,
{
    let (version_bytes, body) = frame
        .split_first_chunk::<2>()
        .ok_or(EdgeLinkError::Truncated)?;
    let version = u16::from_be_bytes(*version_bytes);
    if version != EDGE_LINK_VERSION {
        return Err(EdgeLinkError::UnknownVersion(version));
    }
    ciborium::from_reader(body).map_err(|e| EdgeLinkError::Decode(e.to_string()))
}

fn encode_to_cbor<T>(msg: &T) -> Result<Vec<u8>, EdgeLinkError>
where
    T: Serialize,
{
    let mut buf = Vec::with_capacity(128);
    ciborium::into_writer(msg, &mut buf).map_err(|e| EdgeLinkError::Decode(e.to_string()))?;
    Ok(buf)
}

pub async fn read_edge_to_hub<R>(reader: &mut R) -> Result<EdgeToHub, EdgeLinkError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame_bytes(reader).await?;
    decode_versioned(&frame)
}

pub async fn read_hub_to_edge<R>(reader: &mut R) -> Result<HubToEdge, EdgeLinkError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame_bytes(reader).await?;
    decode_versioned(&frame)
}

pub async fn write_edge_to_hub<W>(writer: &mut W, msg: &EdgeToHub) -> Result<(), EdgeLinkError>
where
    W: AsyncWrite + Unpin,
{
    write_frame_bytes(writer, &encode_to_cbor(msg)?).await
}

pub async fn write_hub_to_edge<W>(writer: &mut W, msg: &HubToEdge) -> Result<(), EdgeLinkError>
where
    W: AsyncWrite + Unpin,
{
    write_frame_bytes(writer, &encode_to_cbor(msg)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;
    use std::io::Cursor;

    fn agent_id() -> AgentId {
        AgentKeypair::generate().id()
    }

    fn tenant_id() -> TenantId {
        TenantId::from_bytes(&[7u8; 32])
    }

    #[tokio::test]
    async fn edge_to_hub_round_trip_hello() {
        let msg = EdgeToHub::Hello {
            edge_id: [3u8; 32],
            iroh_endpoints: vec!["edge.example:51820".into(), "[::1]:51820".into()],
            software_version: "0.1.2".into(),
            psk: [5u8; 32],
        };
        let mut buf = Vec::new();
        write_edge_to_hub(&mut buf, &msg).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_edge_to_hub(&mut cur).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn edge_to_hub_round_trip_session_events() {
        let added = EdgeToHub::SessionAdded {
            agent_id: agent_id(),
            tenant_id: tenant_id(),
        };
        let removed = EdgeToHub::SessionRemoved {
            agent_id: agent_id(),
        };
        for msg in [added, removed] {
            let mut buf = Vec::new();
            write_edge_to_hub(&mut buf, &msg).await.unwrap();
            let mut cur = Cursor::new(buf);
            let got = read_edge_to_hub(&mut cur).await.unwrap();
            assert_eq!(got, msg);
        }
    }

    #[tokio::test]
    async fn hub_to_edge_round_trip_welcome() {
        let msg = HubToEdge::Welcome {
            hub_id: [9u8; 32],
            signing_keys: vec![HubSigningKey {
                kid: 42,
                public_key: vec![0u8; PQ_PUB_KEY_LEN],
            }],
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &msg).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        match got {
            HubToEdge::Welcome {
                hub_id,
                signing_keys,
            } => {
                assert_eq!(hub_id, [9u8; 32]);
                assert_eq!(signing_keys.len(), 1);
                assert_eq!(signing_keys[0].kid, 42);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hub_to_edge_round_trip_port_reservations() {
        let entries = vec![
            PortReservationEntry {
                tenant_id: tenant_id(),
                ip: None,
                port: 22000,
                protocol: "tcp".into(),
            },
            PortReservationEntry {
                tenant_id: tenant_id(),
                ip: Some("2001:db8::1".into()),
                port: 53,
                protocol: "udp".into(),
            },
        ];
        let snapshot = HubToEdge::PortReservationsSnapshot {
            entries: entries.clone(),
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &snapshot).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        match got {
            HubToEdge::PortReservationsSnapshot { entries: got } => assert_eq!(got, entries),
            other => panic!("expected PortReservationsSnapshot, got {other:?}"),
        }

        let delta = HubToEdge::PortReservationsChanged {
            added: entries.clone(),
            removed: vec![],
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &delta).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        match got {
            HubToEdge::PortReservationsChanged { added, removed } => {
                assert_eq!(added, entries);
                assert!(removed.is_empty());
            }
            other => panic!("expected PortReservationsChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn edge_to_hub_round_trip_control_request() {
        let msg = EdgeToHub::ControlRequest {
            request_id: 0xDEAD_BEEF_CAFE_F00D,
            frame: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mut buf = Vec::new();
        write_edge_to_hub(&mut buf, &msg).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_edge_to_hub(&mut cur).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn hub_to_edge_round_trip_control_response() {
        let msg = HubToEdge::ControlResponse {
            request_id: 7,
            status: 0,
            body: vec![0xAA, 0xBB],
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &msg).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        match got {
            HubToEdge::ControlResponse {
                request_id,
                status,
                body,
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(status, 0);
                assert_eq!(body, vec![0xAA, 0xBB]);
            }
            other => panic!("expected ControlResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hub_to_edge_round_trip_route_snapshot() {
        let msg = HubToEdge::RouteSnapshot {
            table: Box::new(RouteTable::default()),
        };
        let mut buf = Vec::new();
        write_hub_to_edge(&mut buf, &msg).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_hub_to_edge(&mut cur).await.unwrap();
        assert!(matches!(got, HubToEdge::RouteSnapshot { .. }));
    }

    #[tokio::test]
    async fn rejects_unknown_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&999u16.to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_edge_to_hub(&mut cur).await.unwrap_err();
        assert!(matches!(err, EdgeLinkError::UnknownVersion(999)));
    }

    #[tokio::test]
    async fn rejects_oversize_frame() {
        let mut buf = Vec::new();
        let oversize = u32::try_from(EDGE_LINK_MAX_FRAME + 1).unwrap();
        buf.extend_from_slice(&oversize.to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_edge_to_hub(&mut cur).await.unwrap_err();
        assert!(matches!(err, EdgeLinkError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn rejects_truncated_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(0u8);
        let mut cur = Cursor::new(buf);
        let err = read_edge_to_hub(&mut cur).await.unwrap_err();
        assert!(matches!(err, EdgeLinkError::Truncated));
    }

    #[test]
    fn hub_signing_key_validates_length() {
        HubSigningKey::new(1, vec![0u8; PQ_PUB_KEY_LEN]).unwrap();
        HubSigningKey::new(1, vec![0u8; 10]).unwrap_err();
    }
}
