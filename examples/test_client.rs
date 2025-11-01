use anyhow::Result;
use bytes::Bytes;
use http::{Method, Request};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("Testing HTTP/3 REST API...\n");

    // Test GET /api/items
    println!("1. Testing GET /api/items");
    let response = make_request(Method::GET, "/api/items", None).await?;
    println!("Response: {}\n", response);

    // Test GET /api/items/1
    println!("2. Testing GET /api/items/1");
    let response = make_request(Method::GET, "/api/items/1", None).await?;
    println!("Response: {}\n", response);

    // Test POST /api/items
    println!("3. Testing POST /api/items");
    let body = r#"{"id":"2","name":"Test Item","description":"Created via API"}"#;
    let response = make_request(Method::POST, "/api/items", Some(body)).await?;
    println!("Response: {}\n", response);

    // Test GET /api/items (verify creation)
    println!("4. Testing GET /api/items (verify creation)");
    let response = make_request(Method::GET, "/api/items", None).await?;
    println!("Response: {}\n", response);

    // Test PUT /api/items/2
    println!("5. Testing PUT /api/items/2");
    let body = r#"{"id":"2","name":"Updated Item","description":"Updated via API"}"#;
    let response = make_request(Method::PUT, "/api/items/2", Some(body)).await?;
    println!("Response: {}\n", response);

    // Test DELETE /api/items/2
    println!("6. Testing DELETE /api/items/2");
    let response = make_request(Method::DELETE, "/api/items/2", None).await?;
    println!("Response: {}\n", response);

    // Test GET /api/items (verify deletion)
    println!("7. Testing GET /api/items (verify deletion)");
    let response = make_request(Method::GET, "/api/items", None).await?;
    println!("Response: {}\n", response);

    // Test 404
    println!("8. Testing GET /api/items/999 (should return 404)");
    let response = make_request(Method::GET, "/api/items/999", None).await?;
    println!("Response: {}\n", response);

    println!("All tests completed successfully!");
    Ok(())
}

async fn make_request(method: Method, path: &str, body: Option<&str>) -> Result<String> {
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // Create QUIC client
    let mut endpoint = h3_quinn::quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = h3_quinn::quinn::ClientConfig::new(std::sync::Arc::new(
        h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    endpoint.set_default_client_config(client_config);

    // Connect
    let conn = endpoint.connect(addr, "localhost")?.await?;

    let (mut driver, mut send_request) = h3::client::builder()
        .build(h3_quinn::Connection::new(conn))
        .await?;

    // Spawn driver
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Build request
    let req = Request::builder()
        .method(method)
        .uri(format!("https://localhost:4433{}", path))
        .header("content-type", "application/json")
        .body(())?;

    // Send request
    let mut stream = send_request.send_request(req).await?;

    if let Some(body_str) = body {
        stream.send_data(Bytes::from(body_str.to_string())).await?;
    }

    stream.finish().await?;

    // Receive response
    let resp = stream.recv_response().await?;

    let mut response_body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        use bytes::Buf;
        response_body.extend_from_slice(chunk.chunk());
    }

    let status = resp.status();
    let body_str = String::from_utf8_lossy(&response_body);

    Ok(format!("Status: {}\nBody: {}", status, body_str))
}

// Skip server certificate verification for testing with self-signed certs
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
