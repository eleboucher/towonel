use std::net::SocketAddr;

use iroh::endpoint::{Connection, Endpoint};
use iroh::{EndpointAddr, RelayMode};
use tokio::io;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use turbo_common::protocol::ALPN_TUNNEL;
use turbo_common::tunnel::{read_hostname_header, write_hostname_header};

/// Start a TCP echo server on a random port. Returns the bound address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = io::copy(&mut read, &mut write).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn tunnel_echo_roundtrip() {
    // 1. Start origin echo server.
    let origin_addr = start_echo_server().await;

    // 2. Create agent-side endpoint (accepts connections).
    let agent_ep = Endpoint::empty_builder(RelayMode::Disabled)
        .alpns(vec![ALPN_TUNNEL.to_vec()])
        .bind()
        .await
        .expect("agent endpoint bind");

    let agent_id = agent_ep.id();
    let agent_sockets = agent_ep.bound_sockets();

    // 3. Create edge-side endpoint (connects to agent).
    let edge_ep = Endpoint::empty_builder(RelayMode::Disabled)
        .bind()
        .await
        .expect("edge endpoint bind");

    // Build an EndpointAddr with the agent's direct socket addresses so the
    // edge can reach it without relay or discovery.
    let mut agent_addr = EndpointAddr::new(agent_id);
    for sock in &agent_sockets {
        agent_addr = agent_addr.with_ip_addr(*sock);
    }

    // 4. Spawn agent-side handler: accept connection, read hostname header,
    //    connect to origin, bidirectional copy.
    //
    //    The agent keeps its QUIC Connection alive (returned via channel) so data
    //    isn't discarded by an early QUIC connection close.
    let (agent_done_tx, agent_done_rx) = oneshot::channel::<Connection>();

    let agent_handle = {
        let agent_ep = agent_ep.clone();
        tokio::spawn(async move {
            let incoming = agent_ep.accept().await.expect("agent accept incoming");
            let conn = incoming.await.expect("agent accept connection");
            let (mut send, mut recv) = conn.accept_bi().await.expect("agent accept bi stream");

            let hostname = read_hostname_header(&mut recv)
                .await
                .expect("agent read hostname header");
            assert_eq!(hostname, "test.example.eu");

            // Connect to origin.
            let origin_stream = tokio::net::TcpStream::connect(origin_addr)
                .await
                .expect("agent connect to origin");

            let (mut origin_read, mut origin_write) = origin_stream.into_split();

            // Forward QUIC -> origin. When the edge finishes sending, this completes.
            io::copy(&mut recv, &mut origin_write)
                .await
                .expect("quic->origin copy");

            // Shut down the TCP write half so the echo server's read returns EOF,
            // which causes it to finish writing echoed data back.
            drop(origin_write);

            // Forward origin -> QUIC. The echo server will close after EOF.
            io::copy(&mut origin_read, &mut send)
                .await
                .expect("origin->quic copy");
            let _ = send.finish();

            // Hand the connection back so it stays alive until the edge reads.
            let _ = agent_done_tx.send(conn);
        })
    };

    // 5. Edge connects to agent, sends hostname header + test data.
    let test_payload = b"hello turbo-tunnel integration test!";

    let conn = edge_ep
        .connect(agent_addr, ALPN_TUNNEL)
        .await
        .expect("edge connect to agent");

    let (mut send, mut recv) = conn.open_bi().await.expect("edge open bi stream");

    write_hostname_header(&mut send, "test.example.eu")
        .await
        .expect("edge write hostname header");

    send.write_all(test_payload)
        .await
        .expect("edge write payload");
    send.finish().expect("edge finish send");

    // 6. Read echoed data back and assert.
    let echoed = recv
        .read_to_end(test_payload.len() + 64)
        .await
        .expect("edge read echoed data");

    assert_eq!(echoed, test_payload, "echoed data must match sent payload");

    // Now safe to let the agent connection drop.
    let _agent_conn = agent_done_rx.await.expect("agent done channel");
    agent_handle.await.expect("agent handler");

    // Cleanup.
    conn.close(0u8.into(), b"done");
    edge_ep.close().await;
    agent_ep.close().await;
}
