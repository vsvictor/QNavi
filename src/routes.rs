use std::sync::Arc;

use anyhow::Result;
use http::{Response, StatusCode};
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use chrono::{Utc, DateTime, Duration as ChronoDuration};
use tracing::{info, debug, warn};

use h3::server::{RequestResolver, RequestStream};

use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, decode, encode, TokenData};
use rand::RngCore;
use rand::rngs::OsRng;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

// Argon2 password hashing
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng as PHOsRng};

// Redis
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use tokio::sync::Mutex;

/// Redis-stored session structure (serialized as JSON)
#[derive(Debug, Serialize, Deserialize)]
struct RedisSession {
    token: String,
    user_id: String,
    expires_at: String, // ISO string
}

#[derive(Clone)]
pub struct Router {
    // Simple in-memory store for users only
    store: Arc<RwLock<Store>>,
    jwt_secret: Arc<Vec<u8>>,
    access_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    // Redis multiplexed connection for sessions wrapped in a Mutex so we can use &mut APIs
    redis: Arc<Mutex<MultiplexedConnection>>,
}

#[derive(Default)]
struct Store {
    users: Vec<User>,
    // sessions moved to Redis
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: Uuid,
    username: String,
    // store password hash (Argon2) instead of plaintext
    password: String,
    created_at: DateTime<Utc>,
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
    pub fn new_with_secret_and_redis(secret: Vec<u8>, redis: Arc<Mutex<MultiplexedConnection>>) -> Self {
        Self {
            store: Arc::new(RwLock::new(Store::default())),
            jwt_secret: Arc::new(secret),
            access_token_ttl_seconds: 60 * 15,    // 15 minutes
            refresh_token_ttl_seconds: 60 * 60 * 24 * 30, // 30 days
            redis,
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(&self.jwt_secret)
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(&self.jwt_secret)
    }

    /// Hash a plaintext password with Argon2 and return the encoded hash string
    fn hash_password(&self, password: &str) -> Result<String> {
        // Generate a random salt
        let salt = SaltString::generate(&mut PHOsRng);
        // Argon2 default parameters (Argon2id)
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("password hashing failed: {:?}", e))?;
        Ok(password_hash.to_string())
    }

    /// Verify a plaintext password against an encoded Argon2 hash
    fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool> {
        let parsed = PasswordHash::new(password_hash)
            .map_err(|e| anyhow::anyhow!("invalid password hash format: {:?}", e))?;
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
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
            ("GET", "/profile") => self.route_getprofile(req.headers()).await?,
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

    // Helper: create JWT access + refresh tokens and persist refresh session into Redis
    async fn create_tokens_for_user(&self, user_id: Uuid) -> Result<(String, String)> {
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

        // measure signing/access token generation
        let start_access = std::time::Instant::now();
        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key())?;
        let access_elapsed = start_access.elapsed();
        debug!("access token signed in {} ms", access_elapsed.as_millis());

        // Refresh token with jti — use OsRng to avoid potential blocking on thread_rng
        let start_rng = std::time::Instant::now();
        let mut jti_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut jti_bytes);
        let rng_elapsed = start_rng.elapsed();
        debug!("jti RNG in {} ms", rng_elapsed.as_millis());
        if rng_elapsed.as_millis() > 200 {
            warn!("RNG took unusually long: {} ms", rng_elapsed.as_millis());
        }
        let jti = hex::encode(jti_bytes);

        // build refresh claims and sign
        let refresh_claims = RefreshClaims {
            sub: user_id.to_string(),
            exp: refresh_exp,
            iat,
            jti: jti.clone(),
        };
        let start_refresh = std::time::Instant::now();
        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key())?;
        let refresh_elapsed = start_refresh.elapsed();
        debug!("refresh token signed in {} ms", refresh_elapsed.as_millis());

        // Persist refresh session into Redis — key: refresh:<jti>
        let session = RedisSession {
            token: refresh_token.clone(),
            user_id: user_id.to_string(),
            expires_at: (now + ChronoDuration::seconds(self.refresh_token_ttl_seconds)).to_rfc3339(),
        };
        let key = format!("refresh:{}", jti);
        let value = serde_json::to_string(&session)?;
        // Set with expiry (seconds)
        let ttl_secs = self.refresh_token_ttl_seconds as u64;

        // Lock the multiplexed connection to get mutable access for AsyncCommands
        let mut conn = self.redis.lock().await;
        // set_ex expects u64 for seconds
        let _: () = conn.set_ex(key, value, ttl_secs).await?;

        // warn if entire generation slow
        let total = access_elapsed + rng_elapsed + refresh_elapsed;
        if total.as_millis() > 500 {
            warn!("token generation total slow: {} ms (access {} ms, rng {} ms, refresh {} ms)",
                total.as_millis(), access_elapsed.as_millis(), rng_elapsed.as_millis(), refresh_elapsed.as_millis());
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

        // Hash password with Argon2
        let password_hash = match self.hash_password(&req.password) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Failed to hash password: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(json!({"error":"internal"}).to_string())?);
            }
        };

        let user = User {
            id: Uuid::new_v4(),
            username: req.username,
            password: password_hash,
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

        // Try to find user (read lock only)
        let maybe_user = {
            let store = self.store.read();
            store.users.iter().find(|u| u.username == req.username).cloned()
        };

        if let Some(user) = maybe_user {
            // Verify password hash
            match self.verify_password(&req.password, &user.password) {
                Ok(true) => {
                    debug!("route_login: password verified, creating tokens (async)");
                    let start = std::time::Instant::now();
                    match self.create_tokens_for_user(user.id).await {
                        Ok((access_token, refresh_token)) => {
                            let elapsed = start.elapsed();
                            if elapsed.as_millis() > 200 {
                                tracing::warn!("token generation slow: {} ms", elapsed.as_millis());
                            } else {
                                debug!("token generation took {} ms", elapsed.as_millis());
                            }

                            let payload = serde_json::json!({ "access_token": access_token, "refresh_token": refresh_token });
                            let body = serde_json::to_string(&payload).unwrap_or_else(|_| "{\"error\":\"serialization_failed\"}".into());
                            debug!("login response length={} valid_json=true", body.len());
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(body)?);
                        }
                        Err(e) => {
                            tracing::error!("route_login: create_tokens failed: {:?}", e);
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .header("content-type", "application/json")
                                .body(json!({"error":"token generation failed","details": format!("{:?}", e)}).to_string())?);
                        }
                    }
                }
                Ok(false) | Err(_) => {
                    // fallthrough to invalid credentials
                }
            }
        }

        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(json!({"error":"invalid credentials"}).to_string())?)
    }

    async fn route_refresh(&self, body: &str) -> Result<Response<String>> {
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

        // decode refresh token (validate signature & exp)
        let token_data: TokenData<RefreshClaims> = match decode::<RefreshClaims>(&rt, &self.decoding_key(), &Validation::default()) {
            Ok(td) => td,
            Err(e) => {
                tracing::warn!("Invalid refresh token: {:?}", e);

                // Diagnostic: manually parse JWT payload without signature verification.
                match rt.split('.').collect::<Vec<&str>>().as_slice() {
                    [hdr_b64, payload_b64, _sig_b64] => {
                        // base64 URL decode payload
                        match URL_SAFE_NO_PAD.decode(payload_b64) {
                            Ok(payload_bytes) => {
                                match serde_json::from_slice::<RefreshClaims>(&payload_bytes) {
                                    Ok(claims) => {
                                        tracing::info!("Insecurely parsed refresh claims (no sig check): {:?}", claims);
                                    }
                                    Err(e) => {
                                        tracing::info!("Parsed JWT payload but failed to deserialize into RefreshClaims: {:?}", e);
                                        tracing::debug!("JWT payload (raw): {}", String::from_utf8_lossy(&payload_bytes));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::info!("Failed to base64-decode JWT payload for diagnostics: {:?}", e);
                            }
                        }

                        // Optionally inspect header too (helpful to check alg)
                        if let Ok(hdr_bytes) = URL_SAFE_NO_PAD.decode(hdr_b64) {
                            tracing::debug!("JWT header (raw): {}", String::from_utf8_lossy(&hdr_bytes));
                        }
                    }
                    _ => {
                        tracing::info!("Token does not look like a JWT (expected three dot-separated parts)");
                    }
                }

                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid refresh token"}).to_string())?);
            }
        };

        // Look up session in Redis by jti and validate stored token matches provided rt
        let jti = token_data.claims.jti.clone();
        let key = format!("refresh:{}", jti);
        let mut conn = self.redis.lock().await;
        let stored_json: Option<String> = conn.get(&key).await?;
        let stored = match stored_json {
            Some(s) => {
                match serde_json::from_str::<RedisSession>(&s) {
                    Ok(sess) => sess,
                    Err(_) => {
                        // malformed data -> remove key and respond unauthorized
                        let _: () = conn.del(&key).await.unwrap_or(());
                        return Ok(Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header("content-type", "application/json")
                            .body(json!({"error":"invalid refresh session"}).to_string())?);
                    }
                }
            }
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid refresh session"}).to_string())?);
            }
        };

        // Ensure the stored token matches provided token (defensive)
        if stored.token != rt {
            // possible token reuse or mismatch
            // for safety, delete stored session
            let _: () = conn.del(&key).await.unwrap_or(());
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .body(json!({"error":"invalid refresh session"}).to_string())?);
        }

        // parse user id
        let user_id = match Uuid::parse_str(&stored.user_id) {
            Ok(u) => u,
            Err(_) => {
                let _: () = conn.del(&key).await.unwrap_or(());
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(json!({"error":"invalid refresh session"}).to_string())?);
            }
        };

        // Now generate new tokens OUTSIDE any lock
        // Drop lock first to avoid holding Redis connection during token generation
        drop(conn);
        let (new_access, new_refresh) = match self.create_tokens_for_user(user_id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to create rotated tokens: {:?}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(json!({"error":"token generation failed"}).to_string())?);
            }
        };

        // Re-acquire connection to remove old session (we already created new one inside create_tokens_for_user)
        let mut conn = self.redis.lock().await;
        let _: () = conn.del(&key).await.unwrap_or(());

        let body = json!({ "access_token": new_access, "refresh_token": new_refresh }).to_string();
        info!("New tokens issued");
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(body)?);
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

        let jti = token_data.claims.jti;
        let key = format!("refresh:{}", jti);
        let mut conn = self.redis.lock().await;
        // remove session
        let deleted: i64 = conn.del(&key).await?;
        if deleted > 0 {
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