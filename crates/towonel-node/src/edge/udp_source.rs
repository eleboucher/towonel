//! Per-datagram destination tracking for the edge UDP listeners.
//!
//! A wildcard-bound socket records no local address, so a plain `send_to` reply
//! takes its source IP from a route lookup. On a multi-homed node that can pick
//! a different address than the client sent to, and the client's connected
//! socket drops the reply. `IP_PKTINFO` / `IPV6_RECVPKTINFO` report the real
//! destination; echoing it back through `sendmsg` pins the reply's source.
//!
//! Linux only. Elsewhere these degrade to `recv_from` / `send_to`.

use std::io;
use std::net::{IpAddr, SocketAddr};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use pktinfo::{cmsg_buffer, enable_recv_dst_addr, recv_from_with_dst, send_to_from};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use fallback::{cmsg_buffer, enable_recv_dst_addr, recv_from_with_dst, send_to_from};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod pktinfo {
    use super::{IpAddr, SocketAddr, io};
    use std::io::{IoSlice, IoSliceMut};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsRawFd;

    use nix::libc;
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg,
        setsockopt, sockopt,
    };
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    /// Reusable scratch space for the inbound pktinfo control message.
    #[must_use]
    pub fn cmsg_buffer() -> Vec<u8> {
        nix::cmsg_space!(libc::in6_pktinfo)
    }

    /// A dual-stack socket reports IPv4 peers through `IPV6_PKTINFO` as
    /// v4-mapped addresses, so the v6 option covers both families; only a
    /// v4-only bind needs `IP_PKTINFO`.
    pub fn enable_recv_dst_addr(sock: &socket2::Socket) -> io::Result<()> {
        if sock.local_addr()?.is_ipv6() {
            setsockopt(sock, sockopt::Ipv6RecvPacketInfo, &true)?;
        } else {
            setsockopt(sock, sockopt::Ipv4PacketInfo, &true)?;
        }
        Ok(())
    }

    /// `recv_from` plus the datagram's destination address, `None` when the
    /// control message was missing or truncated.
    pub async fn recv_from_with_dst(
        socket: &UdpSocket,
        cmsg: &mut Vec<u8>,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        socket
            .async_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(&mut *buf)];
                let msg = recvmsg::<SockaddrStorage>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(cmsg.as_mut_slice()),
                    MsgFlags::empty(),
                )?;
                let peer = msg
                    .address
                    .as_ref()
                    .and_then(storage_to_socket_addr)
                    .ok_or_else(|| {
                        io::Error::other("recvmsg reported no peer address for udp datagram")
                    })?;
                // `cmsgs` errors on a truncated buffer; degrade to an unpinned
                // reply rather than dropping the datagram.
                let dst = msg
                    .cmsgs()
                    .ok()
                    .and_then(|mut cmsgs| cmsgs.find_map(|c| pktinfo_dst_addr(&c)));
                Ok((msg.bytes, peer, dst))
            })
            .await
    }

    /// `send_to` with the reply's source pinned to `src`.
    pub async fn send_to_from(
        socket: &UdpSocket,
        payload: &[u8],
        peer: SocketAddr,
        src: Option<IpAddr>,
    ) -> io::Result<usize> {
        let Some(src) = src else {
            return socket.send_to(payload, peer).await;
        };
        let dst = SockaddrStorage::from(peer);
        socket
            .async_io(Interest::WRITABLE, || {
                let iov = [IoSlice::new(payload)];
                let sent = match src {
                    IpAddr::V4(v4) => {
                        let info = libc::in_pktinfo {
                            ipi_ifindex: 0,
                            // `ipi_spec_dst` is the field that sets the source;
                            // `ipi_addr` is ignored outbound.
                            ipi_spec_dst: libc::in_addr {
                                s_addr: u32::from_ne_bytes(v4.octets()),
                            },
                            ipi_addr: libc::in_addr { s_addr: 0 },
                        };
                        sendmsg(
                            socket.as_raw_fd(),
                            &iov,
                            &[ControlMessage::Ipv4PacketInfo(&info)],
                            MsgFlags::empty(),
                            Some(&dst),
                        )?
                    }
                    IpAddr::V6(v6) => {
                        let info = libc::in6_pktinfo {
                            ipi6_ifindex: 0,
                            ipi6_addr: libc::in6_addr {
                                s6_addr: v6.octets(),
                            },
                        };
                        sendmsg(
                            socket.as_raw_fd(),
                            &iov,
                            &[ControlMessage::Ipv6PacketInfo(&info)],
                            MsgFlags::empty(),
                            Some(&dst),
                        )?
                    }
                };
                Ok(sent)
            })
            .await
    }

    /// Keeps the v4-mapped form for IPv4 peers, matching what `recv_from` on
    /// the same dual-stack socket reports.
    fn storage_to_socket_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
        if let Some(v4) = storage.as_sockaddr_in() {
            return Some(SocketAddr::from(*v4));
        }
        storage.as_sockaddr_in6().map(|v6| SocketAddr::from(*v6))
    }

    fn pktinfo_dst_addr(cmsg: &ControlMessageOwned) -> Option<IpAddr> {
        match cmsg {
            // `ipi_addr` is the IP header destination, i.e. what the client
            // sent to; `ipi_spec_dst` is the local routing destination.
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(IpAddr::V4(Ipv4Addr::from(
                info.ipi_addr.s_addr.to_ne_bytes(),
            ))),
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            IpAddr, SocketAddr, UdpSocket, cmsg_buffer, enable_recv_dst_addr, recv_from_with_dst,
            send_to_from,
        };
        use std::time::Duration;

        /// Mirrors what `bind_udp_port` builds.
        fn wildcard_listener() -> UdpSocket {
            let sock = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            sock.set_only_v6(false).unwrap();
            sock.set_nonblocking(true).unwrap();
            let addr = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0);
            sock.bind(&addr.into()).unwrap();
            enable_recv_dst_addr(&sock).unwrap();
            UdpSocket::from_std(sock.into()).unwrap()
        }

        /// A client on a secondary local address only sees the reply if its
        /// source matches what the client sent to.
        #[tokio::test]
        async fn reply_source_matches_the_address_the_client_sent_to() {
            let listener = wildcard_listener();
            let port = listener.local_addr().unwrap().port();

            let client = UdpSocket::bind("127.0.0.2:0").await.unwrap();
            client.connect(("127.0.0.2", port)).await.unwrap();
            client.send(b"ping").await.unwrap();

            let mut cmsg = cmsg_buffer();
            let mut buf = vec![0u8; 64];
            let (n, peer, dst) = recv_from_with_dst(&listener, &mut cmsg, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf[..n], b"ping");
            assert_eq!(
                dst,
                Some(IpAddr::V6("::ffff:127.0.0.2".parse().unwrap())),
                "kernel should report the v4-mapped destination the client addressed",
            );

            send_to_from(&listener, b"pong", peer, dst).await.unwrap();

            let mut reply = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut reply))
                .await
                .expect("connected client saw no reply, so the source address was wrong")
                .unwrap();
            assert_eq!(&reply[..n], b"pong");
        }

        /// Unpinned, the kernel routes the reply out of 127.0.0.1 and the
        /// connected client rejects it. Keeps the test above from passing
        /// trivially.
        #[tokio::test]
        async fn plain_send_to_reply_is_rejected_by_the_client() {
            let listener = wildcard_listener();
            let port = listener.local_addr().unwrap().port();

            let client = UdpSocket::bind("127.0.0.2:0").await.unwrap();
            client.connect(("127.0.0.2", port)).await.unwrap();
            client.send(b"ping").await.unwrap();

            let mut cmsg = cmsg_buffer();
            let mut buf = vec![0u8; 64];
            let (_, peer, _) = recv_from_with_dst(&listener, &mut cmsg, &mut buf)
                .await
                .unwrap();

            send_to_from(&listener, b"pong", peer, None).await.unwrap();

            let mut reply = vec![0u8; 64];
            let timed_out =
                tokio::time::timeout(Duration::from_millis(500), client.recv(&mut reply))
                    .await
                    .is_err();
            assert!(timed_out, "unpinned reply unexpectedly reached the client");
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod fallback {
    use super::{IpAddr, SocketAddr, io};
    use tokio::net::UdpSocket;

    #[must_use]
    pub fn cmsg_buffer() -> Vec<u8> {
        Vec::new()
    }

    pub fn enable_recv_dst_addr(_sock: &socket2::Socket) -> io::Result<()> {
        Ok(())
    }

    pub async fn recv_from_with_dst(
        socket: &UdpSocket,
        _cmsg: &mut Vec<u8>,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        let (n, peer) = socket.recv_from(buf).await?;
        Ok((n, peer, None))
    }

    pub async fn send_to_from(
        socket: &UdpSocket,
        payload: &[u8],
        peer: SocketAddr,
        _src: Option<IpAddr>,
    ) -> io::Result<usize> {
        socket.send_to(payload, peer).await
    }
}
