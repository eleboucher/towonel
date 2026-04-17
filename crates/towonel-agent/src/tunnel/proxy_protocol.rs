use std::net::SocketAddr;

use ppp::v2;

use towonel_common::tunnel::ClientAddrs;

/// Encode a PROXY v2 PROXY header for a TCP stream.
///
/// Caller guarantees `src` and `dst` share an address family (the common
/// writer in `towonel-common` normalizes v4-mapped v6 on the way in).
pub fn encode_v2(addrs: ClientAddrs) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        same_family(addrs.src, addrs.dst),
        "client-addrs have mismatched families"
    );
    let header = v2::Builder::with_addresses(
        v2::Version::Two | v2::Command::Proxy,
        v2::Protocol::Stream,
        (addrs.src, addrs.dst),
    )
    .build()?;
    Ok(header)
}

const fn same_family(a: SocketAddr, b: SocketAddr) -> bool {
    matches!(
        (a, b),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_v4_round_trips() {
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        };
        let bytes = encode_v2(addrs).unwrap();
        let header = v2::Header::try_from(bytes.as_slice()).unwrap();
        assert_eq!(header.command, v2::Command::Proxy);
        assert!(matches!(header.addresses, v2::Addresses::IPv4(_)));
    }

    #[test]
    fn proxy_v6_round_trips() {
        let addrs = ClientAddrs {
            src: "[2001:db8::1]:54321".parse().unwrap(),
            dst: "[2001:db8::2]:443".parse().unwrap(),
        };
        let bytes = encode_v2(addrs).unwrap();
        let header = v2::Header::try_from(bytes.as_slice()).unwrap();
        assert!(matches!(header.addresses, v2::Addresses::IPv6(_)));
    }

    #[test]
    fn mixed_family_errors() {
        let addrs = ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "[2001:db8::1]:443".parse().unwrap(),
        };
        assert!(encode_v2(addrs).is_err());
    }
}
