use anyhow::{Context, Result};
use bytes::Bytes;
use h3::server::RequestStream;
use h3_quinn::quinn;
use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod tls;

// Simple in-memory data store for demonstration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Item {
    id: String,
    name: String,
    description: String,
}

type DataStore = Arc<RwLock<Vec<Item>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create data store
    let data_store: DataStore = Arc::new(RwLock::new(vec![Item {
        id: "1".to_string(),
        name: "Sample Item".to_string(),
        description: "A sample item for testing".to_string(),
    }]));

    // Generate self-signed certificate for development
    let (cert, key) = tls::generate_self_signed_cert()?;

    // Configure QUIC server
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let server_config = tls::configure_server(cert, key)?;

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("HTTP/3 server listening on {}", addr);
    info!("Available endpoints:");
    info!("  GET    /api/items       - List all items");
    info!("  GET    /api/items/:id   - Get item by ID");
    info!("  POST   /api/items       - Create new item");
    info!("  PUT    /api/items/:id   - Update item");
    info!("  DELETE /api/items/:id   - Delete item");

    // Accept incoming connections
    while let Some(conn) = endpoint.accept().await {
        let store = data_store.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, store).await {
                error!("Connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Incoming, store: DataStore) -> Result<()> {
    let conn = conn.await?;
    info!("New connection from {}", conn.remote_address());

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
        .await
        .context("Failed to create H3 connection")?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(request_resolver)) => {
                let store = store.clone();
                tokio::spawn(async move {
                    match request_resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_request(req, stream, store).await {
                                error!("Request error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Request resolution error: {}", e);
                        }
                    }
                });
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                error!("Accept error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    store: DataStore,
) -> Result<()> {
    let method = req.method();
    let path = req.uri().path();

    info!("{} {}", method, path);

    let (response, body) = match (method, path) {
        (&Method::GET, "/api/items") => handle_list_items(store).await,
        (&Method::GET, path) if path.starts_with("/api/items/") => {
            let id = path.strip_prefix("/api/items/").unwrap();
            handle_get_item(store, id).await
        }
        (&Method::POST, "/api/items") => {
            let body = read_body(&mut stream).await?;
            handle_create_item(store, body).await
        }
        (&Method::PUT, path) if path.starts_with("/api/items/") => {
            let id = path.strip_prefix("/api/items/").unwrap();
            let body = read_body(&mut stream).await?;
            handle_update_item(store, id, body).await
        }
        (&Method::DELETE, path) if path.starts_with("/api/items/") => {
            let id = path.strip_prefix("/api/items/").unwrap();
            handle_delete_item(store, id).await
        }
        _ => {
            let body = serde_json::json!({
                "error": "Not Found",
                "message": format!("Endpoint {} {} not found", method, path)
            });
            let json_str = serde_json::to_string(&body).unwrap();
            let response = build_json_response(StatusCode::NOT_FOUND, json_str.len());
            (response, json_str)
        }
    };

    // Send response
    stream.send_response(response).await?;

    // Send body data
    stream.send_data(Bytes::from(body)).await?;
    stream.finish().await?;

    Ok(())
}

async fn read_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        use bytes::Buf;
        body.extend_from_slice(chunk.chunk());
    }
    Ok(body)
}

async fn handle_list_items(store: DataStore) -> (Response<()>, String) {
    let items = store.read().await;
    let body = serde_json::to_value(&*items).unwrap();
    let json_str = serde_json::to_string(&body).unwrap();
    let response = build_json_response(StatusCode::OK, json_str.len());
    (response, json_str)
}

async fn handle_get_item(store: DataStore, id: &str) -> (Response<()>, String) {
    let items = store.read().await;
    if let Some(item) = items.iter().find(|i| i.id == id) {
        let body = serde_json::to_value(item).unwrap();
        let json_str = serde_json::to_string(&body).unwrap();
        let response = build_json_response(StatusCode::OK, json_str.len());
        (response, json_str)
    } else {
        let body = serde_json::json!({
            "error": "Not Found",
            "message": format!("Item with id '{}' not found", id)
        });
        let json_str = serde_json::to_string(&body).unwrap();
        let response = build_json_response(StatusCode::NOT_FOUND, json_str.len());
        (response, json_str)
    }
}

async fn handle_create_item(store: DataStore, body: Vec<u8>) -> (Response<()>, String) {
    match serde_json::from_slice::<Item>(&body) {
        Ok(item) => {
            let mut items = store.write().await;
            items.push(item.clone());
            let body = serde_json::to_value(&item).unwrap();
            let json_str = serde_json::to_string(&body).unwrap();
            let response = build_json_response(StatusCode::CREATED, json_str.len());
            (response, json_str)
        }
        Err(_) => {
            let body = serde_json::json!({
                "error": "Bad Request",
                "message": "Invalid JSON body"
            });
            let json_str = serde_json::to_string(&body).unwrap();
            let response = build_json_response(StatusCode::BAD_REQUEST, json_str.len());
            (response, json_str)
        }
    }
}

async fn handle_update_item(store: DataStore, id: &str, body: Vec<u8>) -> (Response<()>, String) {
    match serde_json::from_slice::<Item>(&body) {
        Ok(updated_item) => {
            let mut items = store.write().await;
            if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                *item = updated_item.clone();
                let body = serde_json::to_value(&updated_item).unwrap();
                let json_str = serde_json::to_string(&body).unwrap();
                let response = build_json_response(StatusCode::OK, json_str.len());
                (response, json_str)
            } else {
                let body = serde_json::json!({
                    "error": "Not Found",
                    "message": format!("Item with id '{}' not found", id)
                });
                let json_str = serde_json::to_string(&body).unwrap();
                let response = build_json_response(StatusCode::NOT_FOUND, json_str.len());
                (response, json_str)
            }
        }
        Err(_) => {
            let body = serde_json::json!({
                "error": "Bad Request",
                "message": "Invalid JSON body"
            });
            let json_str = serde_json::to_string(&body).unwrap();
            let response = build_json_response(StatusCode::BAD_REQUEST, json_str.len());
            (response, json_str)
        }
    }
}

async fn handle_delete_item(store: DataStore, id: &str) -> (Response<()>, String) {
    let mut items = store.write().await;
    if let Some(pos) = items.iter().position(|i| i.id == id) {
        items.remove(pos);
        let body = serde_json::json!({
            "message": format!("Item with id '{}' deleted successfully", id)
        });
        let json_str = serde_json::to_string(&body).unwrap();
        let response = build_json_response(StatusCode::OK, json_str.len());
        (response, json_str)
    } else {
        let body = serde_json::json!({
            "error": "Not Found",
            "message": format!("Item with id '{}' not found", id)
        });
        let json_str = serde_json::to_string(&body).unwrap();
        let response = build_json_response(StatusCode::NOT_FOUND, json_str.len());
        (response, json_str)
    }
}

fn build_json_response(status: StatusCode, content_length: usize) -> Response<()> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("content-length", content_length.to_string())
        .body(())
        .unwrap()
}
