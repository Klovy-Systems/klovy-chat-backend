pub mod crypto_store;
pub mod frame_crypto;
pub mod handlers;
pub mod registry;
pub mod state;

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, RawQuery, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::decode;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use tokio::sync::{mpsc, watch};

use crate::middlewares::ip_blocker::IPBlockerArc;
use crate::utils::client_ip::client_ip_from_headers;
use crate::utils::security::client_id::{query_client_valid, query_param, WS_CRYPTO_QUERY_PARAM};
use crate::utils::security::origin::is_origin_header_allowed;
use crate::utils::security::transport::is_secure_client_connection;
use crate::ws::crypto_store::{consume_ws_crypto_key, ws_frame_encryption_required};
use crate::ws::frame_crypto::{decrypt_frame, encrypt_frame};
use crate::ws::handlers::{dispatch_message, on_user_connected, on_user_disconnected};
use crate::ws::registry::ConnectionRegistry;
use crate::ws::state::{is_valid_object_id, SocketState};
use crate::middlewares::auth_middleware::TokenPayload;
use crate::model::user_model::User;
use crate::utils::auth::jwt_auth::{
    jwt_decoding_key, parse_jwt_from_cookie_header, parse_refresh_from_cookie_header,
    resolve_session_family_id, user_from_jwt_with_refresh,
};
use crate::utils::auth::jwt_validation::hs256_validation;
use crate::utils::db::get_db;
use crate::utils::whitelist::is_whitelist_enabled;
use mongodb::bson::oid::ObjectId;

#[derive(Clone)]
pub struct WsAppState {
    pub socket_state: SocketState,
    pub registry: ConnectionRegistry,
    pub ip_blocker: Arc<IPBlockerArc>,
}

pub fn init(registry: ConnectionRegistry) {
    registry::set_registry(registry);
}

#[derive(Debug, Deserialize)]
struct IncomingFrame {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    payload: serde_json::Value,
}

const PING_INTERVAL: Duration = Duration::from_secs(45);
const PONG_TIMEOUT: Duration = Duration::from_secs(90);
const AUTH_RECHECK_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PAYLOAD: usize = 1_000_000;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(app_state): State<WsAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if !is_origin_header_allowed(&headers) {
        log::warn!("WebSocket rejected — invalid origin");
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if !is_secure_client_connection(&headers) {
        log::warn!("WebSocket rejected — insecure transport (require HTTPS/WSS in production)");
        return (StatusCode::FORBIDDEN, "Secure connection required").into_response();
    }

    let client_ip = client_ip_from_headers(&headers, Some(peer));

    if app_state.ip_blocker.is_blocked(&client_ip) {
        log::warn!("WebSocket rejected — blocked IP {}", client_ip);
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if !query_client_valid(raw_query.as_deref()) {
        app_state.ip_blocker.add_suspicious_activity(&client_ip);
        log::warn!("WebSocket rejected — missing client identifier for IP {}", client_ip);
        return (StatusCode::BAD_REQUEST, "Unsupported client").into_response();
    }

    if !crate::utils::ratelimit::ws_handshake_allowed(&client_ip) {
        log::warn!("WebSocket rejected — handshake rate limit for IP {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());

    let refresh_token = cookie_header.and_then(parse_refresh_from_cookie_header);
    let refresh_ref = refresh_token.as_deref();

    let (user_id, jwt_token) =
        if let Some(token) = cookie_header.and_then(|h| parse_jwt_from_cookie_header(h)) {
            match user_from_jwt_with_refresh(&token, refresh_ref).await {
                Some(user) => (
                    user.id.map(|id| id.to_hex()).unwrap_or_default(),
                    token,
                ),
                None => (String::new(), String::new()),
            }
        } else {
            (String::new(), String::new())
        };

    if user_id.is_empty() || jwt_token.is_empty() || !is_valid_object_id(&user_id) {
        log::warn!("WebSocket rejected — missing or invalid JWT cookie");
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if is_whitelist_enabled() {
        let allowed = match ObjectId::parse_str(&user_id) {
            Ok(oid) => match User::find_by_id(&get_db(), oid).await {
                Ok(Some(u)) => u.is_whitelisted,
                _ => false,
            },
            Err(_) => false,
        };
        if !allowed {
            log::warn!("WebSocket rejected — user {} not whitelisted", user_id);
            return (StatusCode::FORBIDDEN, "User not whitelisted").into_response();
        }
    }

    let session_family_id = if let Ok(key) = jwt_decoding_key() {
        decode::<TokenPayload>(&jwt_token, &key, &hs256_validation())
            .ok()
            .map(|data| data.claims)
    } else {
        None
    };

    let session_family_id = if let Some(payload) = session_family_id {
        resolve_session_family_id(&payload, refresh_ref).await
    } else {
        None
    };

    if !app_state
        .socket_state
        .register_ip_connection(&client_ip)
        .await
    {
        log::warn!("WebSocket rejected — too many connections from IP {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Too many connections").into_response();
    }

    let encryption_required = ws_frame_encryption_required();
    let crypto_token = query_param(raw_query.as_deref(), WS_CRYPTO_QUERY_PARAM);
    let frame_key = if encryption_required {
        let Some(token) = crypto_token.as_deref() else {
            log::warn!("WebSocket rejected — missing frame encryption token for user {}", user_id);
            app_state
                .socket_state
                .unregister_ip_connection(&client_ip)
                .await;
            return (StatusCode::FORBIDDEN, "Encryption required").into_response();
        };
        match consume_ws_crypto_key(token, &user_id) {
            Some(key) => Some(key),
            None => {
                log::warn!("WebSocket rejected — invalid frame encryption token for user {}", user_id);
                app_state
                    .socket_state
                    .unregister_ip_connection(&client_ip)
                    .await;
                return (StatusCode::FORBIDDEN, "Invalid encryption token").into_response();
            }
        }
    } else {
        crypto_token
            .as_deref()
            .and_then(|token| consume_ws_crypto_key(token, &user_id))
    };

    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            user_id,
            jwt_token,
            refresh_token,
            session_family_id,
            client_ip,
            frame_key,
            app_state,
        )
    })
}

async fn process_incoming_text(
    text: &str,
    connected: &str,
    state: &SocketState,
    tx: &mpsc::Sender<String>,
    last_pong_at: &mut std::time::Instant,
) -> bool {
    // Auth is validated on connect and re-checked on AUTH_RECHECK_INTERVAL.
    // Re-running JWT+DB lookup on every frame (typing, ping, send) added a full
    // Mongo round-trip before the handler could run and stalled the socket loop.
    if let Ok(parsed) = serde_json::from_str::<IncomingFrame>(text) {
        if parsed.msg_type == "pong" {
            *last_pong_at = std::time::Instant::now();
            return true;
        }
        if parsed.msg_type == "ping" {
            *last_pong_at = std::time::Instant::now();
            let _ = tx.try_send(json!({"type":"pong","payload":{}}).to_string());
            return true;
        }
        dispatch_message(connected, &parsed.msg_type, parsed.payload, state).await;
    }

    true
}

async fn handle_socket(
    socket: WebSocket,
    user_id: String,
    jwt_token: String,
    refresh_token: Option<String>,
    session_family_id: Option<String>,
    client_ip: String,
    frame_key: Option<[u8; 32]>,
    app_state: WsAppState,
) {
    if !app_state.socket_state.register_connection(&user_id).await {
        log::warn!("Too many connections for user {}", user_id);
        app_state
            .socket_state
            .unregister_ip_connection(&client_ip)
            .await;
        return;
    }

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(registry::WS_SEND_BUFFER);
    let (revoke_tx, mut revoke_rx) = watch::channel(false);
    let conn_id = app_state
        .registry
        .register(&user_id, tx.clone(), revoke_tx, session_family_id)
        .await;

    on_user_connected(&user_id).await;
    log::info!("User connected: {}", user_id);

    let state = app_state.socket_state.clone();
    let connected = user_id.clone();
    let mut auth_interval = tokio::time::interval(AUTH_RECHECK_INTERVAL);
    auth_interval.tick().await;
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick completes immediately; skip so the first ping is after PING_INTERVAL.
    ping_interval.tick().await;
    let mut last_pong_at = std::time::Instant::now();

    let encryption_required = frame_key.is_some();

    loop {
        tokio::select! {
            _ = revoke_rx.changed() => {
                if *revoke_rx.borrow_and_update() {
                    log::info!("WebSocket session revoked for user {}", user_id);
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if last_pong_at.elapsed() > PONG_TIMEOUT {
                    log::info!("WebSocket pong timeout for user {}", user_id);
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
                if ws_sender
                    .send(Message::Ping(Default::default()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ = auth_interval.tick() => {
                if user_from_jwt_with_refresh(
                    &jwt_token,
                    refresh_token.as_deref(),
                )
                .await
                .is_none()
                {
                    log::info!("WebSocket session expired for user {}", user_id);
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
                if is_whitelist_enabled() {
                    let still_allowed = match ObjectId::parse_str(&user_id) {
                        Ok(oid) => match User::find_by_id(&get_db(), oid).await {
                            Ok(Some(u)) => u.is_whitelisted,
                            _ => false,
                        },
                        Err(_) => false,
                    };
                    if !still_allowed {
                        log::info!("WebSocket closed — whitelist revoked for {}", user_id);
                        let _ = ws_sender.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(text) => {
                        let outbound = if let Some(key) = frame_key {
                            match encrypt_frame(&key, &text) {
                                Ok(bytes) => Message::Binary(bytes.into()),
                                Err(e) => {
                                    log::warn!("WebSocket encrypt failed for user {}: {e}", user_id);
                                    continue;
                                }
                            }
                        } else {
                            Message::Text(text.into())
                        };
                        if ws_sender.send(outbound).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = ws_receiver.next() => {
                match result {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_PAYLOAD {
                            continue;
                        }
                        let text = if let Some(key) = frame_key {
                            match decrypt_frame(&key, &data) {
                                Ok(value) => value,
                                Err(e) => {
                                    log::warn!("WebSocket decrypt failed for user {}: {e}", user_id);
                                    continue;
                                }
                            }
                        } else {
                            continue;
                        };
                        if !process_incoming_text(
                            &text,
                            &connected,
                            &state,
                            &tx,
                            &mut last_pong_at,
                        )
                        .await
                        {
                            let _ = ws_sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if encryption_required {
                            log::warn!("WebSocket rejected plaintext frame for user {}", user_id);
                            continue;
                        }
                        if text.len() > MAX_PAYLOAD {
                            continue;
                        }
                        if !process_incoming_text(
                            &text,
                            &connected,
                            &state,
                            &tx,
                            &mut last_pong_at,
                        )
                        .await
                        {
                            let _ = ws_sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if ws_sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_pong_at = std::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }
    app_state.registry.unregister(&user_id, conn_id).await;
    app_state.socket_state.unregister_connection(&user_id).await;
    app_state
        .socket_state
        .unregister_ip_connection(&client_ip)
        .await;

    // Ustaw offline / wyczyść stan tylko gdy to było OSTATNIE aktywne połączenie
    // użytkownika (inaczej zamknięcie jednej karty wyłączałoby go na innych).
    if !app_state.socket_state.is_user_connected(&user_id).await {
        app_state.socket_state.clear_user_state(&user_id).await;
        on_user_disconnected(&user_id).await;
    }
    log::info!("User disconnected: {}", user_id);
}
