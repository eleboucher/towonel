use iroh::endpoint::{QuicTransportConfig, VarInt};

/// ALPN protocol identifier for towonel agent ↔ edge connections.
pub const ALPN_TUNNEL: &[u8] = b"towonel/tunnel/1";

/// Cap on concurrent in-flight tunnel streams per agent ↔ edge connection.
///
/// Advertised as QUIC `max_concurrent_bidi_streams` and enforced by the
/// agent's accept semaphore; the lower of the two is the real limit.
pub const TUNNEL_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Per-stream receive window.
///
/// One client connection rides one QUIC stream, so this caps single-connection
/// throughput at `window / RTT`; the noq default (1.25 MiB) capped a stream at
/// ~100 Mbit/s at 100 ms RTT.
const TUNNEL_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;

/// Connection-wide receive window. Bounds unread buffered bytes across all
/// streams of a connection (noq defaults to unlimited).
const TUNNEL_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Connection-wide unacked send budget shared by all streams; sized to match
/// [`TUNNEL_RECEIVE_WINDOW`] (noq defaults to 10 MiB).
const TUNNEL_SEND_WINDOW: u64 = 64 * 1024 * 1024;

/// QUIC transport tuning for both tunnel endpoints. Windows are negotiated
/// per side, so an untuned peer silently re-imposes the defaults — keep both
/// ends on this one config.
#[must_use]
pub fn tunnel_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(TUNNEL_MAX_CONCURRENT_STREAMS))
        .stream_receive_window(VarInt::from_u32(TUNNEL_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(TUNNEL_RECEIVE_WINDOW))
        .send_window(TUNNEL_SEND_WINDOW)
        .build()
}
