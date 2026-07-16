use actix_web::HttpRequest;
use mongodb::bson::oid::ObjectId;
use std::env;

use crate::model::user_model::User;
use crate::utils::auth::jwt_auth::{user_id_from_jwt_token, user_from_jwt};

pub const ADMIN_COOKIE: &str = "adminJwt";

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
    !get_admin_user_ids().is_empty()
}

pub fn is_admin_user_id(user_id: &str) -> bool {
    let id = user_id.trim().to_ascii_lowercase();
    if id.is_empty() || ObjectId::parse_str(&id).is_err() {
        return false;
    }
    get_admin_user_ids().iter().any(|allowed| allowed == &id)
}

pub fn user_id_from_request(req: &HttpRequest) -> Option<String> {
    let cookie = req.cookie("jwt")?;
    let token = cookie.value();
    user_id_from_jwt_token(token)
}

pub async fn resolve_admin_user(req: &HttpRequest) -> Option<User> {
    let cookie = req.cookie("jwt")?;
    let token = cookie.value();
    let user = user_from_jwt(token).await?;
    let id = user.id.map(|oid| oid.to_hex())?;
    if !is_admin_user_id(&id) {
        return None;
    }
    Some(user)
}

use crate::utils::app_env::is_production;

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
