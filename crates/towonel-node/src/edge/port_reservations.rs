#![allow(
    dead_code,
    reason = "lookup/len/is_empty consumed by accept-time enforcement"
)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use tracing::warn;

use towonel_common::edge_link::PortReservationEntry;
use towonel_common::identity::TenantId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReservationKey {
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Default)]
pub struct PortReservations {
    inner: RwLock<HashMap<ReservationKey, TenantId>>,
}

impl PortReservations {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn replace_all<'a, I>(&self, entries: I)
    where
        I: IntoIterator<Item = &'a PortReservationEntry>,
    {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clear();
        for entry in entries {
            if let Some((k, v)) = parse_entry(entry) {
                guard.insert(k, v);
            }
        }
    }

    pub fn apply_delta<'a, A, R>(&self, added: A, removed: R)
    where
        A: IntoIterator<Item = &'a PortReservationEntry>,
        R: IntoIterator<Item = &'a PortReservationEntry>,
    {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in removed {
            if let Some((k, _)) = parse_entry(entry) {
                guard.remove(&k);
            }
        }
        for entry in added {
            if let Some((k, v)) = parse_entry(entry) {
                guard.insert(k, v);
            }
        }
    }

    #[must_use]
    pub fn lookup(&self, key: &ReservationKey) -> Option<TenantId> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(key).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn parse_entry(entry: &PortReservationEntry) -> Option<(ReservationKey, TenantId)> {
    let Some(protocol) = Protocol::parse(&entry.protocol) else {
        warn!(
            protocol = %entry.protocol,
            port = entry.port,
            "dropping port reservation with unknown protocol; port may appear unreserved"
        );
        return None;
    };
    let ip = match &entry.ip {
        Some(s) => match s.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(e) => {
                warn!(
                    ip = %s,
                    port = entry.port,
                    error = %e,
                    "dropping port reservation with unparsable ip; port may appear unreserved"
                );
                return None;
            }
        },
        None => None,
    };
    Some((
        ReservationKey {
            ip,
            port: entry.port,
            protocol,
        },
        entry.tenant_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(seed: u8) -> TenantId {
        TenantId::from_bytes(&[seed; 32])
    }

    fn entry(tenant_seed: u8, ip: Option<&str>, port: u16, proto: &str) -> PortReservationEntry {
        PortReservationEntry {
            tenant_id: tid(tenant_seed),
            ip: ip.map(str::to_string),
            port,
            protocol: proto.to_string(),
        }
    }

    #[test]
    fn snapshot_replaces_state() {
        let r = PortReservations::default();
        r.replace_all(&[entry(1, None, 22000, "tcp")]);
        assert_eq!(r.len(), 1);
        r.replace_all(&[entry(2, None, 53, "udp")]);
        assert_eq!(r.len(), 1);
        assert!(
            r.lookup(&ReservationKey {
                ip: None,
                port: 22000,
                protocol: Protocol::Tcp,
            })
            .is_none()
        );
        assert_eq!(
            r.lookup(&ReservationKey {
                ip: None,
                port: 53,
                protocol: Protocol::Udp,
            }),
            Some(tid(2))
        );
    }

    #[test]
    fn delta_adds_and_removes() {
        let r = PortReservations::default();
        r.replace_all(&[entry(1, None, 22000, "tcp")]);
        r.apply_delta(
            &[entry(2, None, 22001, "tcp")],
            &[entry(1, None, 22000, "tcp")],
        );
        assert!(
            r.lookup(&ReservationKey {
                ip: None,
                port: 22000,
                protocol: Protocol::Tcp,
            })
            .is_none()
        );
        assert_eq!(
            r.lookup(&ReservationKey {
                ip: None,
                port: 22001,
                protocol: Protocol::Tcp,
            }),
            Some(tid(2))
        );
    }

    #[test]
    fn ipv6_lookup_round_trip() {
        let r = PortReservations::default();
        r.replace_all(&[entry(3, Some("2001:db8::1"), 8443, "tcp")]);
        let key = ReservationKey {
            ip: Some("2001:db8::1".parse().unwrap()),
            port: 8443,
            protocol: Protocol::Tcp,
        };
        assert_eq!(r.lookup(&key), Some(tid(3)));
    }

    #[test]
    fn unknown_protocol_silently_skipped() {
        let r = PortReservations::default();
        r.replace_all(&[entry(1, None, 22000, "sctp")]);
        assert!(r.is_empty());
    }
}
