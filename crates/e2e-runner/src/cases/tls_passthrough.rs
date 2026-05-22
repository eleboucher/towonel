use std::sync::Arc;

use anyhow::{Result, anyhow, ensure};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::proxy_v2;

pub async fn run(
    edge_host: &str,
    edge_tls_port: u16,
    sni: &str,
    fixture_pem_path: &std::path::Path,
) -> Result<()> {
    let expected_der = load_fixture_leaf_der(fixture_pem_path)?;

    let mut tcp = TcpStream::connect((edge_host, edge_tls_port)).await?;
    let header = proxy_v2::tcp_header(tcp.local_addr()?, tcp.peer_addr()?);
    tcp.write_all(&header).await?;

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name =
        ServerName::try_from(sni.to_string()).map_err(|e| anyhow!("invalid SNI: {e}"))?;

    let tls = connector.connect(server_name, tcp).await?;

    let (_, conn) = tls.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| anyhow!("no peer certificate"))?;

    ensure!(
        leaf.as_ref() == expected_der.as_ref(),
        "leaf cert ({} bytes) != fixture ({} bytes) — edge terminated TLS",
        leaf.as_ref().len(),
        expected_der.as_ref().len(),
    );

    tracing::info!("tls_passthrough: PASS");
    Ok(())
}

fn load_fixture_leaf_der(path: &std::path::Path) -> Result<CertificateDer<'static>> {
    let pem = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("no certificate in {}", path.display()))?
        .map_err(Into::into)
}

/// Skips verification — the test compares the leaf DER manually after the
/// handshake, which is the whole point of this case.
#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}
