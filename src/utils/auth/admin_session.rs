use actix_web::{HttpRequest, HttpResponse};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::net::IpAddr;

use crate::middlewares::auth_middleware::TokenPayload;
use crate::model::refresh_token_model::RefreshToken;
use crate::model::user_model::{User, UserRole};
use crate::utils::auth::panel_permissions::{
    panel_role_label, user_can_manage_panel_roles as can_manage_roles,
    user_has_panel_access, user_has_permission, PanelPermission,
};
use crate::utils::app_env::is_production;
use crate::utils::auth::jwt_auth::{
    jwt_decoding_key, resolve_session_family_id, user_from_jwt_with_refresh,
    user_id_from_jwt_token,
};
use crate::utils::auth::jwt_validation::hs256_validation;
use crate::utils::auth::refresh_token::REFRESH_COOKIE;
use crate::utils::db::get_db;
use crate::utils::security::constant_time::constant_time_eq_str;

pub const ADMIN_COOKIE: &str = "adminJwt";
const ADMIN_ELEVATION_MAX_AGE_SECS: i64 = 8 * 60 * 60;
const ADMIN_ELEVATION_PURPOSE: &str = "admin_panel";

#[derive(Debug, Serialize, Deserialize)]
struct AdminElevationClaims {
    #[serde(rename = "userId")]
    user_id: String,
    purpose: String,
    exp: usize,
}

/// Lista ID użytkowników z bazy (ObjectId hex), rozdzielona przecinkami.
/// Np. `ADMIN_USER_IDS=6a4e5425bc9f2cb279deaa4a,6a515be2534d14681c9965c7`
pub fn get_admin_user_ids() -> Vec<String> {
    let raw = env::var("ADMIN_USER_IDS")
        .or_else(|_| env::var("ADMIN_USER_ID"))
        .unwrap_or_default();

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| ObjectId::parse_str(s).is_ok())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

pub fn admin_user_ids_configured() -> bool {
    true
}

/// ID kont root (ObjectId hex), rozdzielone przecinkami — bootstrap bez ręcznej edycji MongoDB.
/// Np. `ROOT_USER_IDS=6a4e5425bc9f2cb279deaa4a`
pub fn get_root_user_ids() -> Vec<String> {
    let raw = env::var("ROOT_USER_IDS")
        .or_else(|_| env::var("ROOT_USER_ID"))
        .unwrap_or_default();

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| ObjectId::parse_str(s).is_ok())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

pub fn user_id_is_env_root(user_id: &str) -> bool {
    let id = user_id.trim().to_ascii_lowercase();
    get_root_user_ids().iter().any(|root_id| root_id == &id)
}

pub fn user_is_root(user: &User) -> bool {
    if user.role == UserRole::Root {
        return true;
    }
    user.id
        .map(|oid| user_id_is_env_root(&oid.to_hex()))
        .unwrap_or(false)
}

/// Dostęp do panelu: rola support i wyżej (oraz root z env).
pub fn user_is_panel_admin(user: &User) -> bool {
    user_has_panel_access(user)
}

pub fn panel_role_for_user(user: &User) -> Option<&'static str> {
    panel_role_label(user)
}

pub fn user_can_manage_panel_roles(user: &User) -> bool {
    can_manage_roles(user)
}

pub async fn require_panel_permission(
    req: &HttpRequest,
    permission: PanelPermission,
) -> Result<User, HttpResponse> {
    let user = resolve_admin_user(req).await.ok_or_else(|| {
        HttpResponse::Unauthorized().json(json!({ "error": "Brak uprawnień do panelu." }))
    })?;
    if !user_has_permission(&user, permission) {
        return Err(HttpResponse::Forbidden().json(json!({
            "error": "Brak uprawnień do tej operacji.",
        })));
    }
    Ok(user)
}

pub async fn is_panel_admin_user_id(user_id: &str) -> bool {
    let id = user_id.trim();
    let Ok(oid) = ObjectId::parse_str(id) else {
        return false;
    };
    User::find_by_id(&get_db(), oid)
        .await
        .ok()
        .flatten()
        .map(|user| user_is_panel_admin(&user))
        .unwrap_or(false)
}

/// Zachowane dla starszych wywołań — preferuj `user_is_panel_admin` / `is_panel_admin_user_id`.
pub fn is_admin_user_id(user_id: &str) -> bool {
    let _ = user_id;
    false
}

fn admin_secret() -> Option<String> {
    env::var("ADMIN_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn admin_elevation_required() -> bool {
    is_production() && admin_secret().is_some_and(|s| s.len() >= 16)
}

pub fn verify_admin_secret(provided: &str) -> bool {
    let Some(expected) = admin_secret() else {
        return false;
    };
    constant_time_eq_str(provided.trim(), &expected)
}

/// Dozwolone adresy IP dla panelu administratora (opcjonalnie).
/// Np. `ADMIN_ALLOWED_IPS=203.0.113.10,198.51.100.0/24,2001:db8::1`
/// Gdy puste — brak filtrowania po IP (zachowanie wsteczne).
pub fn get_admin_allowed_ips() -> Vec<String> {
    env::var("ADMIN_ALLOWED_IPS")
        .or_else(|_| env::var("ADMIN_IP_ALLOWLIST"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn admin_ip_allowlist_configured() -> bool {
    !get_admin_allowed_ips().is_empty()
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if let Some(v4) = v6.to_ipv4_mapped() => IpAddr::V4(v4),
        other => other,
    }
}

fn ipv4_cidr_contains(network: std::net::Ipv4Addr, prefix: u8, ip: std::net::Ipv4Addr) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

fn ipv6_cidr_contains(network: std::net::Ipv6Addr, prefix: u8, ip: std::net::Ipv6Addr) -> bool {
    if prefix > 128 {
        return false;
    }
    let net = network.octets();
    let addr = ip.octets();
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = prefix % 8;

    if net[..full_bytes] != addr[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    if full_bytes >= net.len() {
        return false;
    }
    let mask = 0xFF_u8 << (8 - rem_bits);
    (net[full_bytes] & mask) == (addr[full_bytes] & mask)
}

fn allowlist_entry_matches(entry: &str, ip: &IpAddr) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }

    if let Some((network, prefix)) = entry.split_once('/') {
        let Ok(prefix) = prefix.trim().parse::<u8>() else {
            return false;
        };
        let Ok(network_ip) = network.trim().parse::<IpAddr>() else {
            return false;
        };
        return match (normalize_ip(network_ip), *ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => ipv4_cidr_contains(net, prefix, addr),
            (IpAddr::V6(net), IpAddr::V6(addr)) => ipv6_cidr_contains(net, prefix, addr),
            _ => false,
        };
    }

    entry
        .parse::<IpAddr>()
        .ok()
        .map(normalize_ip)
        .map(|allowed| allowed == *ip)
        .unwrap_or(false)
}

pub fn is_admin_ip_allowed(client_ip: &str) -> bool {
    if !admin_ip_allowlist_configured() {
        return true;
    }

    let trimmed = client_ip.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return false;
    }

    let Ok(parsed) = trimmed.parse::<IpAddr>() else {
        return false;
    };
    let ip = normalize_ip(parsed);

    get_admin_allowed_ips()
        .iter()
        .any(|entry| allowlist_entry_matches(entry, &ip))
}

pub fn user_id_from_request(req: &HttpRequest) -> Option<String> {
    let cookie = req.cookie("jwt")?;
    let token = cookie.value();
    user_id_from_jwt_token(token)
}

async fn session_is_bound(req: &HttpRequest, token: &str) -> bool {
    if !is_production() {
        return true;
    }

    let refresh_token = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string());
    if refresh_token.is_none() {
        return false;
    }

    let Ok(key) = jwt_decoding_key() else {
        return false;
    };
    let Ok(data) = decode::<TokenPayload>(token, &key, &hs256_validation()) else {
        return false;
    };

    let Some(family_id) =
        resolve_session_family_id(&data.claims, refresh_token.as_deref()).await
    else {
        return false;
    };

    RefreshToken::family_is_active(&get_db(), &family_id)
        .await
        .unwrap_or(false)
}

/// Zalogowany użytkownik komunikatora (bez sprawdzania isAdmin).
pub async fn resolve_chat_session_user(req: &HttpRequest) -> Option<User> {
    let cookie = req.cookie("jwt")?;
    let token = cookie.value().trim();
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let refresh_token = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string());
    if !session_is_bound(req, token).await {
        return None;
    }

    user_from_jwt_with_refresh(token, refresh_token.as_deref()).await
}

/// Konto panelu admina po pełnej walidacji sesji użytkownika (jwt + refresh + isAdmin).
pub async fn resolve_panel_admin_account(req: &HttpRequest) -> Option<User> {
    let cookie = req.cookie("jwt")?;
    let token = cookie.value().trim();
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let refresh_token = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string());
    if !session_is_bound(req, token).await {
        return None;
    }

    let user = user_from_jwt_with_refresh(token, refresh_token.as_deref()).await?;
    if !user_is_panel_admin(&user) {
        return None;
    }
    Some(user)
}

fn admin_elevation_decoding_key() -> Option<DecodingKey> {
    admin_secret().map(|secret| DecodingKey::from_secret(secret.as_bytes()))
}

fn admin_elevation_encoding_key() -> Option<EncodingKey> {
    admin_secret().map(|secret| EncodingKey::from_secret(secret.as_bytes()))
}

pub fn admin_elevation_valid(req: &HttpRequest, user_id: &str) -> bool {
    if !admin_elevation_required() {
        return true;
    }

    let token = req
        .cookie(ADMIN_COOKIE)
        .map(|cookie| cookie.value().trim().to_string())
        .unwrap_or_default();
    if token.is_empty() || token.len() > 2048 {
        return false;
    }

    let key = match admin_elevation_decoding_key() {
        Some(key) => key,
        None => return false,
    };

    let claims = match decode::<AdminElevationClaims>(&token, &key, &admin_elevation_validation()) {
        Ok(data) => data.claims,
        Err(_) => return false,
    };

    claims.purpose == ADMIN_ELEVATION_PURPOSE
        && claims.user_id.eq_ignore_ascii_case(user_id)
}

const PANEL_HANDOFF_MAX_AGE_SECS: i64 = 90;
const PANEL_HANDOFF_PURPOSE: &str = "panel_handoff";

#[derive(Debug, Serialize, Deserialize)]
pub struct PanelHandoffClaims {
    pub jwt: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub purpose: String,
    pub exp: usize,
}

fn panel_handoff_decoding_key() -> Result<DecodingKey, String> {
    crate::utils::auth::jwt_auth::jwt_decoding_key()
}

fn panel_handoff_encoding_key() -> Result<EncodingKey, String> {
    let secret = crate::utils::auth::jwt_auth::jwt_secret()?;
    Ok(EncodingKey::from_secret(secret.as_bytes()))
}

pub fn issue_panel_handoff_token(
    user_id: &str,
    jwt: &str,
    refresh_token: &str,
    csrf: Option<&str>,
) -> Result<String, String> {
    let encoding_key = panel_handoff_encoding_key()?;
    let exp = (chrono::Utc::now().timestamp() + PANEL_HANDOFF_MAX_AGE_SECS) as usize;
    let claims = PanelHandoffClaims {
        jwt: jwt.to_string(),
        refresh_token: refresh_token.to_string(),
        csrf: csrf.map(str::to_string),
        user_id: user_id.to_string(),
        purpose: PANEL_HANDOFF_PURPOSE.to_string(),
        exp,
    };
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &encoding_key,
    )
    .map_err(|e| e.to_string())
}

pub fn redeem_panel_handoff_token(token: &str) -> Result<PanelHandoffClaims, String> {
    let token = token.trim();
    if token.is_empty() || token.len() > 8192 {
        return Err("Invalid handoff token".to_string());
    }
    let key = panel_handoff_decoding_key()?;
    let mut validation = hs256_validation();
    validation.validate_exp = true;
    let claims = decode::<PanelHandoffClaims>(&token, &key, &validation)
        .map_err(|_| "Invalid or expired handoff token".to_string())?
        .claims;
    if claims.purpose != PANEL_HANDOFF_PURPOSE {
        return Err("Invalid handoff token purpose".to_string());
    }
    Ok(claims)
}

pub async fn resolve_admin_user(req: &HttpRequest) -> Option<User> {
    let user = resolve_panel_admin_account(req).await?;
    let id = user.id.map(|oid| oid.to_hex())?;
    if admin_elevation_required() && !admin_elevation_valid(req, &id) {
        return None;
    }
    Some(user)
}

pub fn issue_admin_elevation_cookie(user_id: &str) -> Result<actix_web::cookie::Cookie<'static>, String> {
    let encoding_key = admin_elevation_encoding_key()
        .ok_or_else(|| "ADMIN_SECRET is not configured".to_string())?;

    let exp = (chrono::Utc::now().timestamp() + ADMIN_ELEVATION_MAX_AGE_SECS) as usize;
    let claims = AdminElevationClaims {
        user_id: user_id.to_ascii_lowercase(),
        purpose: ADMIN_ELEVATION_PURPOSE.to_string(),
        exp,
    };

    let token = encode(
        &crate::utils::auth::jwt_validation::hs256_header(),
        &claims,
        &encoding_key,
    )
    .map_err(|e| e.to_string())?;

    Ok(build_admin_cookie(
        &token,
        ADMIN_ELEVATION_MAX_AGE_SECS * 1000,
    ))
}

fn admin_elevation_validation() -> Validation {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    validation
}

pub fn build_admin_cookie(value: &str, max_age_ms: i64) -> actix_web::cookie::Cookie<'static> {
    use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};

    Cookie::build(ADMIN_COOKIE, value.to_string())
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::milliseconds(max_age_ms))
        .finish()
}

pub fn clear_admin_cookie() -> actix_web::cookie::Cookie<'static> {
    build_admin_cookie("", 0)
}
