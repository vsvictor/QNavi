use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::filter::EnvFilter;

mod routes;
use routes::Router;

#[tokio::main]
async fn main() -> Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Server address
    let addr: SocketAddr = "0.0.0.0:4433".parse()?;

    // Generate self-signed certificate (for local dev) as DER bytes.
    let (cert_der, key_der) = generate_self_signed_cert_der()?;

    // Import pki wrapper types from rustls-pki-types crate (stable public types).
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    // Convert DER bytes into the CertificateDer / PrivateKeyDer wrappers.
    let cert_chain: Vec<CertificateDer<'static>> = vec![CertificateDer::from(cert_der.clone())];
    let priv_key: PrivateKeyDer<'static> =
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der.clone()));

    // Build server config
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, priv_key)?;

    // Configure transport
    let mut transport_config = quinn::TransportConfig::default();
    use quinn_proto::VarInt;
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(100));
    server_config.transport = Arc::new(transport_config);

    // Build endpoint (no need for `mut` here)
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("Listening on {}", addr);

    // Router contains in-memory "storage" for users & tokens
    let router = Arc::new(Router::new());

    // Accept incoming connections and spawn a task to handle each
    while let Some(connecting) = endpoint.accept().await {
        let router = router.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    info!("Connection established: addr={}", conn.remote_address());
                    if let Err(e) = handle_connection(conn, router).await {
                        error!("Connection failed: {:?}", e);
                    }
                }
                Err(e) => error!("failed to accept connection: {:?}", e),
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connection, router: Arc<Router>) -> Result<()> {
    // Wrap quinn connection in h3_quinn::Connection so it implements h3::quic::Connection
    let h3_conn = h3_quinn::Connection::new(conn);

    // Build H3 server over the h3_quinn connection using h3 API
    let server_builder = h3::server::builder();
    let mut h3_connection = server_builder.build(h3_conn).await?;

    // accept loop
    let router_task = router.clone();
    let connection_task = tokio::spawn(async move {
        loop {
            match h3_connection.accept().await {
                Ok(Some(resolver)) => {
                    let router = router_task.clone();
                    tokio::spawn(async move {
                        if let Err(e) = router.handle_request(resolver).await {
                            tracing::error!("Request handling error: {:?}", e);
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::error!("h3 accept error: {:?}", e);
                    break;
                }
            }
        }
    });

    connection_task.await?;
    Ok(())
}

/// Generate a self-signed certificate pair for local testing and return DER bytes.
fn generate_self_signed_cert_der() -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();
    Ok((cert_der, key_der))
}