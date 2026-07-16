use jsonwebtoken::{decode, DecodingKey};
use mongodb::bson::oid::ObjectId;
use std::env;

use crate::middlewares::auth_middleware::TokenPayload;
use crate::model::refresh_token_model::RefreshToken;
use crate::model::user_model::User;
use crate::utils::app_env::is_production;
use crate::utils::auth::jwt_validation::hs256_validation;
use crate::utils::auth::refresh_token::family_id_from_refresh_token;
use crate::utils::db::get_db;

pub fn jwt_secret() -> Result<String, String> {
    let key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    if key.trim().is_empty() {
        return Err("JWT_KEY is empty".to_string());
    }
    if is_production() && key.len() < 32 {
        return Err("JWT_KEY must be at least 32 characters in production".to_string());
    }
    Ok(key)
}

pub fn jwt_decoding_key() -> Result<DecodingKey, String> {
    Ok(DecodingKey::from_secret(jwt_secret()?.as_bytes()))
}

pub fn parse_jwt_from_cookie_header(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("jwt=") {
            let token = value.trim();
            if !token.is_empty() && token.len() <= 1000 {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub fn parse_refresh_from_cookie_header(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("refreshToken=") {
            let token = value.trim();
            if !token.is_empty() && token.len() <= 128 {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub fn user_id_from_jwt_token(token: &str) -> Option<String> {
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let key = jwt_decoding_key().ok()?;
    let payload = decode::<TokenPayload>(token, &key, &hs256_validation())
        .ok()?
        .claims;

    if payload.user_id.is_empty() || ObjectId::parse_str(&payload.user_id).is_err() {
        return None;
    }

    Some(payload.user_id)
}

pub async fn resolve_session_family_id(
    payload: &TokenPayload,
    refresh_token: Option<&str>,
) -> Option<String> {
    if let Some(ref family_id) = payload.session_family_id {
        if !family_id.is_empty() {
            return Some(family_id.clone());
        }
        return None;
    }

    if let Some(raw) = refresh_token {
        return family_id_from_refresh_token(raw).await;
    }

    None
}

pub fn session_family_from_jwt(token: &str) -> Option<String> {
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let key = jwt_decoding_key().ok()?;
    let payload = decode::<TokenPayload>(token, &key, &hs256_validation())
        .ok()?
        .claims;

    payload
        .session_family_id
        .filter(|id| !id.is_empty())
}

pub async fn user_from_jwt(token: &str) -> Option<User> {
    user_from_jwt_with_refresh(token, None).await
}

pub async fn user_from_jwt_with_refresh(
    token: &str,
    refresh_token: Option<&str>,
) -> Option<User> {
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let key = jwt_decoding_key().ok()?;
    let payload = decode::<TokenPayload>(token, &key, &hs256_validation())
        .ok()?
        .claims;

    user_from_token_payload(&payload, refresh_token).await
}

pub async fn user_from_token_payload(
    payload: &TokenPayload,
    refresh_token: Option<&str>,
) -> Option<User> {
    if payload.user_id.is_empty() {
        return None;
    }

    let user_id = ObjectId::parse_str(&payload.user_id).ok()?;
    let db = get_db();
    let user = User::find_by_id(&db, user_id).await.ok()??;

    if user.token_version != payload.token_version {
        return None;
    }
    if !user.is_login_allowed() {
        return None;
    }

    let family_id = resolve_session_family_id(payload, refresh_token).await;
    if let Some(ref family_id) = family_id {
        let active = RefreshToken::family_is_active(&db, family_id)
            .await
            .unwrap_or(false);
        if !active {
            return None;
        }
    }

    Some(user)
}
