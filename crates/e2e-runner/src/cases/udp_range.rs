use anyhow::{Result, ensure};

use super::udp_echo::{echo_roundtrip, no_reply};

/// Exercises a UDP port-range service. The origin echoes `"<port>:<payload>"`,
/// so a matching prefix proves the datagram reached the origin on the *same*
/// port it entered the edge (same-port forwarding). A port just past the range
/// must have no listener.
pub async fn run(edge_host: &str, range_start: u16, range_end: u16) -> Result<()> {
    let mid = range_start + (range_end - range_start) / 2;
    for port in [range_start, mid, range_end] {
        let reply = echo_roundtrip(edge_host, port, b"ping", 10).await?;
        let text = String::from_utf8_lossy(&reply);
        ensure!(
            text.starts_with(&format!("{port}:")),
            "port {port}: expected same-port echo, got {text:?}"
        );
    }

    let outside = range_end + 1;
    ensure!(
        no_reply(edge_host, outside).await?,
        "port {outside} outside the range should not be forwarded"
    );
    tracing::info!("udp_range: PASS");
    Ok(())
}
