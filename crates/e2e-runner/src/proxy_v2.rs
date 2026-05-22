use std::net::SocketAddr;

use ppp::v2::{self, Builder};

pub fn tcp_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    Builder::with_addresses(
        v2::Version::Two | v2::Command::Proxy,
        v2::Protocol::Stream,
        (src, dst),
    )
    .build()
    .expect("matching src/dst families always serialize")
}
