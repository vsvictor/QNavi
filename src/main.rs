use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc, path::Path, time::Duration};

use anyhow::{anyhow, Result};
use tracing::{error, info};
use tracing_subscriber::filter::EnvFilter;

mod routes;
use routes::Router;

// Bring RngCore into scope so ThreadRng.fill_bytes is available
use rand::RngCore;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Server address
    let addr: SocketAddr = "0.0.0.0:4433".parse()?;

    // Prepare JWT secret: read from SECRET_KEY env or generate ephemeral one.
    let secret_key: Vec<u8> = match std::env::var("SECRET_KEY") {
        Ok(s) if !s.is_empty() => {
            info!("Using SECRET_KEY from environment");
            s.into_bytes()
        }
        _ => {
            // generate 32 random bytes
            let mut b = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            tracing::warn!("No SECRET_KEY provided — generated ephemeral secret; tokens won't survive restart");
            b
        }
    };

    // Prepare Redis connection (read REDIS_URL from env, default to local)
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    info!("Connecting to Redis at {}", redis_url);
    let redis_client = redis::Client::open(redis_url.as_str())
        .map_err(|e| anyhow!("failed to create redis client: {:?}", e))?;

    // Create a multiplexed tokio connection (redis 0.32.x)
    let multiplexed = redis::Client::get_multiplexed_tokio_connection(&redis_client)
        .await
        .map_err(|e| anyhow!("failed to create redis multiplexed connection: {:?}", e))?;

    // Wrap in Mutex and Arc to match Router API (Arc<Mutex<MultiplexedConnection>>)
    let redis_arc = Arc::new(tokio::sync::Mutex::new(multiplexed));

    // Create router with secret and redis
    let router = Arc::new(Router::new_with_secret_and_redis(secret_key, redis_arc.clone()));

    // Try to load cert/key from .env-specified PEM files; fallback to generated self-signed.
    let cert_key = load_certificates_and_key_from_env().or_else(|_| {
        // Fallback: generate self-signed cert if env not provided or parsing failed
        generate_self_signed_cert_der().map(|(c, k)| (vec![c], k))
    })?;

    let (cert_chain_vec, key_der_vec) = cert_key;

    // Convert to rustls-pki-types wrappers expected by quinn-proto
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    // Certificates: CertificateDer::from(Vec<u8>)
    let cert_chain: Vec<CertificateDer<'static>> = cert_chain_vec
        .into_iter()
        .map(|c| CertificateDer::from(c))
        .collect();

    // Private key: try to detect format and wrap appropriately
    // Try PKCS8 first, then PKCS1 (RSA), then SEC1 (EC)
    let priv_key: PrivateKeyDer<'static> = {
        // Try wrapping as PKCS8
        if let Ok(pk8) = try_wrap_pkcs8(&key_der_vec) {
            PrivateKeyDer::from(pk8)
        } else if let Ok(pkcs1) = try_wrap_pkcs1(&key_der_vec) {
            PrivateKeyDer::from(pkcs1)
        } else if let Ok(sec1) = try_wrap_sec1(&key_der_vec) {
            PrivateKeyDer::from(sec1)
        } else {
            return Err(anyhow!("unsupported or invalid private key format; supported: PKCS8, PKCS1, SEC1"));
        }
    };

    // Build server config
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, priv_key)?;

    // Configure transport
    let mut transport_config = quinn::TransportConfig::default();
    use quinn_proto::VarInt;
    // concurrent streams
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(100));

    // max_idle_timeout expects Option<quinn_proto::IdleTimeout>, which implements From<VarInt>.
    // Convert desired timeout (Duration) into milliseconds and pass as VarInt.
    // Here we set 600 seconds = 600_000 milliseconds.
    let idle_timeout_ms: u32 = (Duration::from_secs(600).as_millis())
        .try_into()
        .unwrap_or(u32::MAX);
    transport_config.max_idle_timeout(Some(quinn_proto::IdleTimeout::from(VarInt::from_u32(idle_timeout_ms))));

    server_config.transport = Arc::new(transport_config);

    // Build endpoint
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("Listening on {}", addr);

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
            tracing::debug!("h3: waiting for next request/resolver");
            match h3_connection.accept().await {
                Ok(Some(resolver)) => {
                    tracing::debug!("h3: resolver received");
                    let router = router_task.clone();
                    tokio::spawn(async move {
                        if let Err(e) = router.handle_request(resolver).await {
                            tracing::error!("Request handling error: {:?}", e);
                        }
                    });
                }
                Ok(None) => {
                    tracing::info!("h3: connection closed by peer");
                    break;
                }
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

/// Try to load certificate chain and private key DER bytes from files specified in .env:
/// CERT_PATH=/path/to/cert_chain.pem (may contain one or more CERTIFICATE blocks)
/// KEY_PATH=/path/to/privkey.pem (PKCS8 / PKCS1 / SEC1)
fn load_certificates_and_key_from_env() -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    use std::env;

    let cert_path = match env::var("CERT_PATH") {
        Ok(p) if !p.is_empty() => p,
        _ => return Err(anyhow!("CERT_PATH not set")),
    };
    let key_path = match env::var("KEY_PATH") {
        Ok(p) if !p.is_empty() => p,
        _ => return Err(anyhow!("KEY_PATH not set")),
    };
    info!("Certificates and private key loaded");
    let certs = load_certs_from_pem(&cert_path)?;
    let key = load_key_from_pem(&key_path)?;

    Ok((certs, key))
}

/// Load one-or-more CERTIFICATE entries from PEM file, returning Vec<Vec<u8>> of DER certs.
fn load_certs_from_pem<P: AsRef<Path>>(path: P) -> Result<Vec<Vec<u8>>> {
    let file = File::open(&path).map_err(|e| anyhow!("failed to open cert file {}: {}", path.as_ref().display(), e))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| anyhow!("failed to parse certificate PEM {}: {}", path.as_ref().display(), e))?;
    if certs.is_empty() {
        return Err(anyhow!("no CERTIFICATE blocks found in {}", path.as_ref().display()));
    }
    Ok(certs)
}

/// Load private key DER bytes by parsing PEM file.
/// Supports PKCS8 (PKCS8Key), RSA (RSAKey / PKCS1) and EC keys (ECKey / SEC1).
fn load_key_from_pem<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let file = File::open(&path).map_err(|e| anyhow!("failed to open key file {}: {}", path.as_ref().display(), e))?;
    let mut reader = BufReader::new(file);

    // rustls_pemfile::read_one returns the first recognized item (PKCS8, RSA, EC)
    // We'll try to read all items and pick the first key-type item.
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(key),
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(key),
            Some(_) => continue, // skip certificates / other blocks
            None => break,
        }
    }

    Err(anyhow!("no private key found in {}", path.as_ref().display()))
}

/// Try to wrap Vec<u8> into PrivatePkcs8KeyDer
fn try_wrap_pkcs8(key: &[u8]) -> Result<rustls_pki_types::PrivatePkcs8KeyDer<'static>> {
    Ok(rustls_pki_types::PrivatePkcs8KeyDer::from(key.to_vec()))
}

/// Try to wrap Vec<u8> into PrivatePkcs1KeyDer
fn try_wrap_pkcs1(key: &[u8]) -> Result<rustls_pki_types::PrivatePkcs1KeyDer<'static>> {
    Ok(rustls_pki_types::PrivatePkcs1KeyDer::from(key.to_vec()))
}

/// Try to wrap Vec<u8> into PrivateSec1KeyDer
fn try_wrap_sec1(key: &[u8]) -> Result<rustls_pki_types::PrivateSec1KeyDer<'static>> {
    Ok(rustls_pki_types::PrivateSec1KeyDer::from(key.to_vec()))
}

/// Generate a self-signed certificate pair for local testing and return DER bytes.
/// Used as fallback if no CERT_PATH/KEY_PATH provided.
fn generate_self_signed_cert_der() -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();
    Ok((cert_der, key_der))
}