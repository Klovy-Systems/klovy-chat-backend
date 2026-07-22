pub mod slowmode;

use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Store {
    buckets: Mutex<HashMap<String, Bucket>>,
    max: u32,
    window: Duration,
}

struct Bucket {
    count: u32,
    reset: Instant,
}

impl Store {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max,
            window,
        }
    }

    pub fn is_over_limit(&self, key: &str) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match map.get(key) {
            Some(b) if now < b.reset => b.count >= self.max,
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    pub fn check_and_increment(&self, key: &str) -> bool {
        self.check_and_increment_with_window(key, self.max, self.window)
    }

    pub fn check_and_increment_with_window(&self, key: &str, max: u32, window: Duration) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            count: 0,
            reset: now + window,
        });
        if now >= bucket.reset {
            bucket.count = 0;
            bucket.reset = now + window;
        }
        if bucket.count >= max {
            return false;
        }
        bucket.count += 1;
        true
    }

    pub fn increment(&self, key: &str) {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            count: 0,
            reset: now + self.window,
        });
        if now >= bucket.reset {
            bucket.count = 0;
            bucket.reset = now + self.window;
        }
        bucket.count += 1;
    }

    /// Seconds until the current window resets (at least 1 when blocked).
    pub fn retry_after_secs(&self, key: &str) -> u64 {
        let map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match map.get(key) {
            Some(b) if now < b.reset => b.reset.duration_since(now).as_secs().max(1),
            _ => self.window.as_secs().max(1),
        }
    }

    /// Atomically checks quota and consumes one slot. Returns retry-after seconds on failure.
    pub fn try_consume(&self, key: &str) -> Result<(), u64> {
        if self.check_and_increment(key) {
            Ok(())
        } else {
            Err(self.retry_after_secs(key))
        }
    }
}

use crate::middlewares::auth_middleware::RequestUserId;

fn client_ip(req: &ServiceRequest) -> String {
    crate::utils::client_ip::client_ip_from_service_request(req)
}

fn rate_limit_key(prefix: &str, ip: &str) -> String {
    format!("{prefix}:{ip}")
}

fn too_many(error: &str, retry_after: i64) -> HttpResponse {
    HttpResponse::TooManyRequests()
        .json(serde_json::json!({ "error": error, "retryAfter": retry_after }))
}

async fn limit_all(
    store: &Store,
    prefix: &str,
    error: &str,
    retry_after: i64,
    trusted_ips: Option<&[String]>,
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let ip = client_ip(&req);

    if let Some(trusted) = trusted_ips {
        if trusted.iter().any(|t| t == &ip) {
            return Ok(next.call(req).await?.map_into_left_body());
        }
    }

    let key = rate_limit_key(prefix, &ip);
    if !store.check_and_increment(&key) {
        let (req, _) = req.into_parts();
        return Ok(ServiceResponse::new(req, too_many(error, retry_after)).map_into_right_body());
    }

    Ok(next.call(req).await?.map_into_left_body())
}

async fn limit_failures(
    store: &Store,
    prefix: &str,
    error: &str,
    retry_after: i64,
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let ip = client_ip(&req);
    let key = rate_limit_key(prefix, &ip);

    if store.is_over_limit(&key) {
        let (req, _) = req.into_parts();
        return Ok(ServiceResponse::new(req, too_many(error, retry_after)).map_into_right_body());
    }

    let res = next.call(req).await?;
    if res.status().as_u16() >= 400 {
        store.increment(&key);
    }
    Ok(res.map_into_left_body())
}

fn trusted_ips() -> Vec<String> {
    std::env::var("TRUSTED_IPS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
        .unwrap_or_default()
}

// NOTE on tuning: limits that gate normal real-time usage (browsing, loading
// media, uploading, discovery, admin panels) are set generously so production
// feels responsive. Security-sensitive limits (login/2FA/signup/password/
// username brute-force) stay strict.
static GLOBAL: Lazy<Store> = Lazy::new(|| Store::new(1500, Duration::from_secs(15 * 60)));
static SEND: Lazy<Store> = Lazy::new(|| Store::new(900, Duration::from_secs(60)));
static AUTH: Lazy<Store> = Lazy::new(|| Store::new(10, Duration::from_secs(15 * 60)));
static LOGIN: Lazy<Store> = Lazy::new(|| Store::new(8, Duration::from_secs(15 * 60)));
static TWO_FACTOR_LOGIN: Lazy<Store> = Lazy::new(|| Store::new(8, Duration::from_secs(15 * 60)));
static SIGNUP: Lazy<Store> = Lazy::new(|| {
    Store::new(
        crate::utils::registration::signup_max_per_ip_hour(),
        Duration::from_secs(60 * 60),
    )
});
static ADMIN_READ: Lazy<Store> = Lazy::new(|| Store::new(200, Duration::from_secs(5 * 60)));
static ADMIN_WRITE: Lazy<Store> = Lazy::new(|| Store::new(60, Duration::from_secs(5 * 60)));
static DISCOVERY: Lazy<Store> = Lazy::new(|| Store::new(60, Duration::from_secs(60)));
static REFRESH: Lazy<Store> = Lazy::new(|| Store::new(120, Duration::from_secs(15 * 60)));
static UPLOAD: Lazy<Store> = Lazy::new(|| Store::new(60, Duration::from_secs(60)));
static INVITE_ACCEPT: Lazy<Store> = Lazy::new(|| Store::new(15, Duration::from_secs(15 * 60)));
static FRIEND_REQUEST: Lazy<Store> = Lazy::new(|| Store::new(40, Duration::from_secs(60 * 60)));
static CHANNEL_REPORT: Lazy<Store> = Lazy::new(|| Store::new(10, Duration::from_secs(15 * 60)));
static TWO_FACTOR_MUTATION: Lazy<Store> = Lazy::new(|| Store::new(10, Duration::from_secs(15 * 60)));
static INVITE_PREVIEW: Lazy<Store> = Lazy::new(|| Store::new(60, Duration::from_secs(15 * 60)));
static WS_HANDSHAKE: Lazy<Store> = Lazy::new(|| Store::new(60, Duration::from_secs(60)));
static CHANGE_PASSWORD: Lazy<Store> = Lazy::new(|| Store::new(5, Duration::from_secs(15 * 60)));
static CHANGE_USERNAME: Lazy<Store> = Lazy::new(|| Store::new(5, Duration::from_secs(15 * 60)));
static FRIEND_ACTION: Lazy<Store> = Lazy::new(|| Store::new(120, Duration::from_secs(5 * 60)));
static CHAT_ATTACHMENT: Lazy<Store> = Lazy::new(|| {
    Store::new(
        crate::utils::upload_limits::MAX_CHAT_ATTACHMENTS_PER_WINDOW,
        crate::utils::upload_limits::chat_attachment_window(),
    )
});

fn chat_attachment_key(user_id: &str) -> String {
    rate_limit_key("chat-attachment", user_id)
}

/// Rolling quota for DM/channel file uploads (images, documents, voice notes, etc.).
pub fn try_consume_chat_attachment_quota(user_id: &str) -> Result<(), u64> {
    CHAT_ATTACHMENT.try_consume(&chat_attachment_key(user_id))
}

pub fn chat_attachment_retry_after_secs(user_id: &str) -> u64 {
    CHAT_ATTACHMENT.retry_after_secs(&chat_attachment_key(user_id))
}

pub async fn global_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let trusted = trusted_ips();
    limit_all(
        &GLOBAL,
        "global",
        "Too many requests from this IP, please try again later.",
        15 * 60 * 1000,
        Some(&trusted),
        req,
        next,
    )
    .await
}

pub async fn send_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &SEND,
        "send",
        "Too many messages sent, please slow down.",
        60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn auth_rate_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_failures(
        &AUTH,
        "auth",
        "Too many authentication attempts, please try again later.",
        15 * 60 * 1000,
        req,
        next,
    )
    .await
}

pub async fn login_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_failures(
        &LOGIN,
        "login",
        "Too many login attempts. Try again in 15 minutes.",
        900,
        req,
        next,
    )
    .await
}

pub async fn two_factor_login_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_failures(
        &TWO_FACTOR_LOGIN,
        "2fa",
        "Too many two-factor attempts. Try again in 15 minutes.",
        900,
        req,
        next,
    )
    .await
}

pub async fn signup_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &SIGNUP,
        "signup",
        "Too many signup attempts. Try again in 1 hour.",
        3600,
        None,
        req,
        next,
    )
    .await
}

pub async fn admin_action_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let is_read = matches!(req.method().as_str(), "GET" | "HEAD");
    let (store, error, retry_after) = if is_read {
        (
            &ADMIN_READ,
            "Too many admin requests. Slow down.",
            300,
        )
    } else {
        (
            &ADMIN_WRITE,
            "Too many admin actions. Slow down.",
            300,
        )
    };

    limit_all(store, "admin", error, retry_after, None, req, next).await
}

pub async fn refresh_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &REFRESH,
        "refresh",
        "Too many token refresh attempts. Try again later.",
        15 * 60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn upload_limiter(
    req: ServiceRequest,
    next: Next<actix_web::body::BoxBody>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let ip = client_ip(&req);
    let ip_key = rate_limit_key("upload", &ip);
    if !UPLOAD.check_and_increment(&ip_key) {
        let (req, _) = req.into_parts();
        return Ok(
            ServiceResponse::new(
                req,
                too_many("Too many file uploads. Slow down.", 60),
            )
            .map_into_boxed_body(),
        );
    }

    let user_id = req
        .extensions()
        .get::<RequestUserId>()
        .map(|user| user.0.clone());
    if let Some(user_id) = user_id {
        let user_key = rate_limit_key("upload-user", &user_id);
        if !UPLOAD.check_and_increment(&user_key) {
            let (req, _) = req.into_parts();
            return Ok(
                ServiceResponse::new(
                    req,
                    too_many("Too many file uploads. Slow down.", 60),
                )
                .map_into_boxed_body(),
            );
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn invite_accept_limiter(
    req: ServiceRequest,
    next: Next<actix_web::body::BoxBody>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    let ip = client_ip(&req);
    let key = rate_limit_key("invite-accept", &ip);
    if !INVITE_ACCEPT.check_and_increment(&key) {
        let (req, _) = req.into_parts();
        return Ok(
            ServiceResponse::new(
                req,
                too_many(
                    "Too many invite accept attempts. Try again later.",
                    15 * 60 * 1000,
                ),
            )
            .map_into_boxed_body(),
        );
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn discovery_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &DISCOVERY,
        "discovery",
        "Too many search requests. Slow down.",
        60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn friend_request_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &FRIEND_REQUEST,
        "friend-request",
        "Too many friend requests. Try again later.",
        3600,
        None,
        req,
        next,
    )
    .await
}

pub async fn channel_report_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &CHANNEL_REPORT,
        "channel-report",
        "Too many reports. Try again later.",
        15 * 60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn two_factor_mutation_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &TWO_FACTOR_MUTATION,
        "2fa-mutation",
        "Too many two-factor changes. Try again later.",
        15 * 60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn invite_preview_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &INVITE_PREVIEW,
        "invite-preview",
        "Too many invite preview requests. Try again later.",
        15 * 60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn friend_action_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_all(
        &FRIEND_ACTION,
        "friend-action",
        "Too many friend actions. Slow down.",
        5 * 60 * 1000,
        None,
        req,
        next,
    )
    .await
}

pub async fn change_password_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_failures(
        &CHANGE_PASSWORD,
        "change-password",
        "Too many password change attempts. Try again in 15 minutes.",
        15 * 60 * 1000,
        req,
        next,
    )
    .await
}

pub async fn change_username_limiter(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    limit_failures(
        &CHANGE_USERNAME,
        "change-username",
        "Too many username change attempts. Try again in 15 minutes.",
        15 * 60 * 1000,
        req,
        next,
    )
    .await
}

pub fn ws_handshake_allowed(ip: &str) -> bool {
    let key = rate_limit_key("ws-handshake", ip);
    WS_HANDSHAKE.check_and_increment(&key)
}
