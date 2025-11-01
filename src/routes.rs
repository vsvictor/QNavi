use std::sync::Arc;

use anyhow::Result;
use http::{Response, StatusCode};
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use chrono::{Utc, DateTime};

use h3::server::{RequestResolver, RequestStream};

#[derive(Clone)]
pub struct Router {
    // Simple in-memory store
    store: Arc<RwLock<Store>>,
}

#[derive(Default)]
struct Store {
    users: Vec<User>,
    sessions: Vec<Session>,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: Uuid,
    username: String,
    // In production — store password hashes
    password: String,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    token: String,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(Store::default())),
        }
    }

    /// Handle an accepted RequestResolver from h3::server::Connection::accept()
    pub async fn handle_request(
        &self,
        resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    ) -> Result<()> {
        // resolve_request returns (http::Request<()>, RequestStream)
        let (req, mut stream): (http::Request<()>, RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>) =
            resolver.resolve_request().await?;
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        tracing::info!("{} {}", method, path);

        // Read body from stream (if any). RequestStream provides recv_data().await -> Result<Option<impl Buf>, _>
        let mut body_bytes = BytesMut::new();
        while let Some(buf_opt) = stream.recv_data().await? {
            // buf_opt implements bytes::Buf — copy its contents into BytesMut
            let mut b = buf_opt;
            while b.has_remaining() {
                let take = std::cmp::min(4096, b.remaining());
                let mut v = vec![0u8; take];
                let n = std::cmp::min(v.len(), b.remaining());
                b.copy_to_slice(&mut v[..n]);
                body_bytes.extend_from_slice(&v[..n]);
            }
        }
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Route
        let response: Response<String> = match (method.as_str(), path.as_str()) {
            ("POST", "/register") => self.route_register(&body_str).await?,
            ("POST", "/login") => self.route_login(&body_str).await?,
            ("POST", "/refresh") => self.route_refresh(&body_str).await?,
            ("GET", "/getprofile") => self.route_getprofile(req.headers()).await?,
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(json!({"error": "not found"}).to_string())?,
        };

        // send response using RequestStream API
        let mut resp_builder = http::Response::builder().status(response.status());
        for (k, v) in response.headers().iter() {
            resp_builder = resp_builder.header(k.as_str(), v.as_bytes());
        }
        let resp_head = resp_builder.body(())?;
        stream.send_response(resp_head).await?;
        stream.send_data(Bytes::from(response.into_body())).await?;
        stream.finish().await?;

        Ok(())
    }

    async fn route_register(&self, body: &str) -> Result<Response<String>> {
        #[derive(Deserialize)]
        struct Req { username: String, password: String }

        let req: Req = serde_json::from_str(body)?;
        // Very naive uniqueness check
        let mut store = self.store.write();
        if store.users.iter().any(|u| u.username == req.username) {
            return Ok(Response::builder()
                .status(StatusCode::CONFLICT)
                .header("content-type", "application/json")
                .body(json!({"error":"user exists"}).to_string())?);
        }
        let user = User {
            id: Uuid::new_v4(),
            username: req.username,
            password: req.password,
            created_at: Utc::now(),
        };
        store.users.push(user.clone());
        let body = json!({
            "id": user.id.to_string(),
            "username": user.username
        }).to_string();
        Ok(Response::builder()
            .status(StatusCode::CREATED)
            .header("content-type", "application/json")
            .body(body)?)
    }

    async fn route_login(&self, body: &str) -> Result<Response<String>> {
        #[derive(Deserialize)]
        struct Req { username: String, password: String }

        let req: Req = serde_json::from_str(body)?;
        let mut store = self.store.write();
        if let Some(user) = store.users.iter().find(|u| u.username == req.username && u.password == req.password) {
            // Create session token (naive)
            let token = format!("tok-{}", Uuid::new_v4());
            let sess = Session {
                token: token.clone(),
                user_id: user.id,
                expires_at: Utc::now() + chrono::Duration::hours(24),
            };
            store.sessions.push(sess);
            let body = json!({ "token": token }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(body)?);
        }
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"invalid credentials"}).to_string())?)
    }

    async fn route_refresh(&self, body: &str) -> Result<Response<String>> {
        #[derive(Deserialize)]
        struct Req { token: String }

        let req: Req = serde_json::from_str(body)?;
        let mut store = self.store.write();
        if let Some(sess) = store.sessions.iter_mut().find(|s| s.token == req.token) {
            // extend expiry
            sess.expires_at = Utc::now() + chrono::Duration::hours(24);
            let body = json!({"token": sess.token, "expires_at": sess.expires_at}).to_string();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(body)?);
        }
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"invalid token"}).to_string())?)
    }

    async fn route_getprofile(&self, headers: &http::HeaderMap) -> Result<Response<String>> {
        // Expect Authorization: Bearer <token>
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        if let Some(token) = auth.strip_prefix("Bearer ").map(|s| s.to_string()) {
            let store = self.store.read();
            if let Some(sess) = store.sessions.iter().find(|s| s.token == token && s.expires_at > Utc::now()) {
                if let Some(user) = store.users.iter().find(|u| u.id == sess.user_id) {
                    let body = json!({
                        "id": user.id.to_string(),
                        "username": user.username,
                        "created_at": user.created_at
                    }).to_string();
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(body)?);
                }
            }
        }
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"unauthenticated"}).to_string())?)
    }
}