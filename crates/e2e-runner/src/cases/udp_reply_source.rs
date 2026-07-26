use anyhow::{Result, ensure};

use super::udp_echo::echo_roundtrip;

/// Reaches the UDP echo service on a secondary address of the edge (a `/32`
/// alias on the same interface as its primary address), which is where reply
/// source selection goes wrong: routing back to the client picks the interface's
/// primary address, and `echo_roundtrip`'s connected socket rejects a reply from
/// anything other than the address it sent to. Passes only when the edge pins
/// the reply source to the datagram's real destination.
pub async fn run(edge_vip: &str, port: u16) -> Result<()> {
    let payload = b"hello-udp-vip";
    let reply = echo_roundtrip(edge_vip, port, payload, 10).await?;
    ensure!(reply == payload, "udp vip echo mismatch: {reply:?}");
    tracing::info!("udp_reply_source: PASS");
    Ok(())
}
