use std::sync::Arc;

use anyhow::Result;
use http::{Response, StatusCode};
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use chrono::{Utc, DateTime, Duration as ChronoDuration};
use tracing::{info, debug};

use h3::server::{RequestResolver, RequestStream};

use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, decode, encode, TokenData};
use rand::RngCore;

#[derive(Clone)]
pub struct Router {
    // Simple in-memory store
    store: Arc<RwLock<Store>>,
    jwt_secret: Arc<Vec<u8>>,
    access_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
}

#[derive(Default)]
struct Store {
    users: Vec<User>,
    sessions: Vec<Session>, // stores refresh tokens
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
    refresh_jti: String, // unique id for refresh JWT (jti)
    token: String,       // refresh token JWT
    user_id: Uuid,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessClaims {
    sub: String, // user id
    exp: usize,
    iat: usize,
    // optional jti for access if desired
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshClaims {
    sub: String, // user id
    exp: usize,
    iat: usize,
    jti: String, // unique id for this refresh token
}

impl Router {
    pub fn new_with_secret(secret: Vec<u8>) -> Self {
        Self {
            store: Arc::new(RwLock::new(Store::default())),
            jwt_secret: Arc::new(secret),
            access_token_ttl_seconds: 60 * 15,    // 15 minutes
            refresh_token_ttl_seconds: 60 * 60 * 24 * 30, // 30 days
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(&self.jwt_secret)
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(&self.jwt_secret)
    }

    /// Helper: parse JSON body into T; on error return a 400 Response
    fn parse_json_bad_request<'a, T>(body: &'a str) -> Result<T, Response<String>>
    where
        T: serde::de::Deserialize<'a>,
    {
        match serde_json::from_str::<T>(body) {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = json!({ "error": "invalid request body", "details": e.to_string() }).to_string();
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    .body(msg)
                    .unwrap();
                Err(resp)
            }
        }
    }

    /// Handle an accepted RequestResolver from h3::server::Connection::accept()
    /// Logs method, path, headers and body.
    pub async fn handle_request(
        &self,
        resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    ) -> Result<()> {
        // resolve_request returns (http::Request<()>, RequestStream)
        let (req, mut stream): (http::Request<()>, RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>) =
            resolver.resolve_request().await?;
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Log request line and headers
        info!(method = %method, path = %path, "Incoming request");
        for (name, value) in req.headers().iter() {
            debug!(header = %name.as_str(), value = %format_args!("{:?}", value), "Header");
        }

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
        debug!(body = %body_str, "Request body");

        // Route
        let response: Response<String> = match (method.as_str(), path.as_str()) {
            ("POST", "/register") => self.route_register(&body_str).await?,
            ("POST", "/login") => self.route_login(&body_str).await?,
            ("POST", "/refresh") => self.route_refresh(&body_str).await?,
            ("POST", "/logout") => self.route_logout(&body_str).await?,
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
        stream.send_data(Bytes::from(response.clone().into_body())).await?;
        stream.finish().await?;

        // Log returned JSON
        info!(response = %response.into_body(), "Return JSON");

        Ok(())
    }

    // Helper: create JWT access + refresh tokens and persist refresh session
    fn create_tokens_for_user(&self, user_id: Uuid) -> Result<(String, String)> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let access_exp = (now + ChronoDuration::seconds(self.access_token_ttl_seconds)).timestamp() as usize;
        let refresh_exp = (now + ChronoDuration::seconds(self.refresh_token_ttl_seconds)).timestamp() as usize;

        // Access token claims
        let access_claims = AccessClaims {
            sub: user_id.to_string(),
            exp: access_exp,
            iat,
        };
        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key())?;

        // Refresh token with jti
        let mut jti_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut jti_bytes);
        let jti = hex::encode(jti_bytes);

        let refresh_claims = RefreshClaims {
            sub: user_id.to_string(),
            exp: refresh_exp,
            iat,
            jti: jti.clone(),
        };
        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key())?;

        // Persist refresh session — hold write lock only briefly
        {
            let mut store = self.store.write();
            store.sessions.push(Session {
                refresh_jti: jti.clone(),
                token: refresh_token.clone(),
                user_id,
                expires_at: (now + ChronoDuration::seconds(self.refresh_token_ttl_seconds)),
            });
        }

        Ok((access_token, refresh_token))
    }

    async fn route_register(&self, body: &str) -> Result<Response<String>> {
        #[derive(Deserialize)]
        struct Req { username: String, password: String }

        let req: Req = match Self::parse_json_bad_request::<Req>(body) {
            Ok(r) => r,
            Err(resp) => return Ok(resp),
        };

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
        debug!("route_login: start");
        #[derive(Deserialize)]
        struct Req { username: String, password: String }

        let req: Req = match Self::parse_json_bad_request::<Req>(body) {
            Ok(r) => r,
            Err(resp) => return Ok(resp),
        };

        debug!("route_login: parsed req for {}", req.username);

        // Try to find user
        let maybe_user = {
            let store = self.store.read();
            store.users.iter().find(|u| u.username == req.username && u.password == req.password).cloned()
        };

        if let Some(user) = maybe_user {
            debug!("route_login: user found, creating tokens");
            // create tokens but protect with timeout
            match tokio::time::timeout(std::time::Duration::from_secs(5), tokio::task::spawn_blocking({
                let this = self.clone();
                move || this.create_tokens_for_user(user.id)
            })).await {
                Ok(Ok(Ok((access_token, refresh_token)))) => {
                    let body = json!({ "access_token": access_token, "refresh_token": refresh_token }).to_string();
                    debug!("route_login: tokens created");
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(body)?);
                }
                Ok(Ok(Err(e))) => {
                    tracing::error!("route_login: create_tokens failed: {:?}", e);
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(json!({"error":"token generation failed","details": format!("{:?}", e)}).to_string())?);
                }
                Ok(Err(join_err)) => {
                    tracing::error!("route_login: spawn_blocking join error: {:?}", join_err);
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(json!({"error":"internal"}).to_string())?);
                }
                Err(_) => {
                    tracing::error!("route_login: create_tokens timed out");
                    return Ok(Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .header("content-type", "application/json")
                        .body(json!({"error":"token generation timeout"}).to_string())?);
                }
            }
        }

        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"invalid credentials"}).to_string())?)
    }

    async fn route_refresh(&self, body: &str) -> Result<Response<String>> {
        info!("Input data:{}", body);
        #[derive(Deserialize)]
        struct Req { refresh_token: Option<String> }

        let req: Req = match Self::parse_json_bad_request::<Req>(body) {
            Ok(r) => r,
            Err(resp) => return Ok(resp),
        };

        let rt = match req.refresh_token {
            Some(t) => {
                info!("Refresh token: {}", t);
                t
            },
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    .body(json!({"error": "missing field", "field": "refresh_token"}).to_string())?);
            }
        };

        // decode refresh token
        let token_data: TokenData<RefreshClaims> = match decode::<RefreshClaims>(&rt, &self.decoding_key(), &Validation::default()) {
            Ok(td) => td,
            Err(e) => {
                tracing::warn!("Invalid refresh token: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid refresh token"}).to_string())?);
            }
        };

        // Validate session exists and jti matches and not expired
        let mut store = self.store.write();
        if let Some(sess) = store.sessions.iter_mut().find(|s| s.refresh_jti == token_data.claims.jti && s.token == rt) {
            if sess.expires_at <= Utc::now() {
                // remove expired
                store.sessions.retain(|s| s.refresh_jti != token_data.claims.jti);
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"refresh token expired"}).to_string())?);
            }

            // issue new access token (and optionally rotate refresh token)
            let user_id = sess.user_id;
            // Simple rotation: create new refresh token and replace session
            let (new_access, new_refresh) = self.create_tokens_for_user(user_id)?;
            // remove old session with same jti
            store.sessions.retain(|s| s.refresh_jti != token_data.claims.jti);

            let body = json!({ "access_token": new_access, "refresh_token": new_refresh }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(body)?);
        }

        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"invalid refresh session"}).to_string())?)
    }

    // Logout: accept refresh_token, revoke it
    async fn route_logout(&self, body: &str) -> Result<Response<String>> {
        #[derive(Deserialize)]
        struct Req { refresh_token: Option<String> }

        let req: Req = match Self::parse_json_bad_request::<Req>(body) {
            Ok(r) => r,
            Err(resp) => return Ok(resp),
        };

        let rt = match req.refresh_token {
            Some(t) => t,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    .body(json!({"error": "missing field", "field": "refresh_token"}).to_string())?);
            }
        };

        // decode to read jti
        let token_data: TokenData<RefreshClaims> = match decode::<RefreshClaims>(&rt, &self.decoding_key(), &Validation::default()) {
            Ok(td) => td,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid refresh token"}).to_string())?);
            }
        };

        // remove session
        let mut store = self.store.write();
        let initial_len = store.sessions.len();
        store.sessions.retain(|s| s.refresh_jti != token_data.claims.jti);
        if store.sessions.len() < initial_len {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(json!({"ok": true}).to_string())?);
        }

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(json!({"error":"refresh token not found"}).to_string())?)
    }

    async fn route_getprofile(&self, headers: &http::HeaderMap) -> Result<Response<String>> {
        // Expect Authorization: Bearer <access_token>
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        let token = match auth.strip_prefix("Bearer ").map(|s| s.to_string()) {
            Some(t) => t,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"unauthenticated"}).to_string())?);
            }
        };

        // decode access token
        let token_data = match decode::<AccessClaims>(&token, &self.decoding_key(), &Validation::default()) {
            Ok(td) => td,
            Err(e) => {
                tracing::warn!("Invalid access token: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid access token"}).to_string())?);
            }
        };

        // token subject is user id
        let user_id = match Uuid::parse_str(&token_data.claims.sub) {
            Ok(u) => u,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid token subject"}).to_string())?);
            }
        };

        let store = self.store.read();
        if let Some(user) = store.users.iter().find(|u| u.id == user_id) {
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

        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"unauthenticated"}).to_string())?)
    }
}