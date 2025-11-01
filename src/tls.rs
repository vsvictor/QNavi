use anyhow::Result;
use quinn::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// Generate a self-signed certificate for development purposes
pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = cert.cert.into();

    Ok((vec![cert_der], key))
}

/// Configure the QUIC server with TLS settings
pub fn configure_server(
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    // Install the default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));

    // Configure transport parameters
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(100u32.into());
    transport_config.max_concurrent_uni_streams(100u32.into());

    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}
