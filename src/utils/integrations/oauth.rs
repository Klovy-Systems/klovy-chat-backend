use mongodb::bson::{oid::ObjectId, DateTime};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;

use crate::model::oauth_token_model::OauthToken;
use crate::model::user_model::ConnectedAccount;
use crate::utils::auth::jwt_auth::jwt_secret;
use crate::utils::crypto::keyed_hash::{hmac_sha256_hex, verify_hmac_sha256_hex};
use crate::utils::db::get_db;

use super::providers::OAuthProviderDef;

#[derive(Debug, Clone)]
pub struct ProviderCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct GenericTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
}

pub fn provider_credentials(def: &OAuthProviderDef) -> Option<ProviderCredentials> {
    let prefix = def.env_prefix;
    let client_id = env::var(format!("{prefix}_CLIENT_ID"))
        .ok()
        .or_else(|| {
            if prefix == "TIKTOK" {
                env::var("TIKTOK_CLIENT_KEY").ok()
            } else {
                None
            }
        })
        .or_else(|| {
            if prefix == "YOUTUBE" {
                env::var("GOOGLE_CLIENT_ID").ok()
            } else {
                None
            }
        })
        .or_else(|| {
            if prefix == "XBOX" {
                env::var("MICROSOFT_CLIENT_ID").ok()
            } else {
                None
            }
        })?;
    let client_secret = env::var(format!("{prefix}_CLIENT_SECRET"))
        .ok()
        .or_else(|| {
            if prefix == "TIKTOK" {
                env::var("TIKTOK_CLIENT_SECRET").ok()
            } else {
                None
            }
        })
        .or_else(|| {
            if prefix == "YOUTUBE" {
                env::var("GOOGLE_CLIENT_SECRET").ok()
            } else {
                None
            }
        })
        .or_else(|| {
            if prefix == "XBOX" {
                env::var("MICROSOFT_CLIENT_SECRET").ok()
            } else {
                None
            }
        })?;
    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return None;
    }
    let redirect_uri = resolve_redirect_uri(def)?;
    Some(ProviderCredentials {
        client_id: client_id.trim().to_string(),
        client_secret: client_secret.trim().to_string(),
        redirect_uri,
    })
}

pub fn resolve_redirect_uri(def: &OAuthProviderDef) -> Option<String> {
    let prefix = def.env_prefix;
    if let Ok(raw) = env::var(format!("{prefix}_REDIRECT_URI")) {
        if !raw.trim().is_empty() {
            return Some(normalize_redirect_uri(raw.trim()));
        }
    }
    env::var("FRONTEND_URL")
        .ok()
        .map(|f| {
            normalize_redirect_uri(&format!(
                "{}/api/integrations/{}/callback",
                f.trim().trim_end_matches('/'),
                def.id
            ))
        })
        .filter(|u| !u.is_empty())
}

fn normalize_redirect_uri(uri: &str) -> String {
    uri.replace("://localhost", "://127.0.0.1")
}

pub fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn base64_url_encode_no_pad(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 63) as usize] as char);
        out.push(CHARS[((triple >> 12) & 63) as usize] as char);
        if i + 1 < input.len() {
            out.push(CHARS[((triple >> 6) & 63) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(CHARS[(triple & 63) as usize] as char);
        }
        i += 3;
    }
    out
}

pub fn generate_pkce_pair() -> (String, String) {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let verifier: String = (0..64)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    let challenge = base64_url_encode_no_pad(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn oauth_state_key() -> Result<Vec<u8>, String> {
    Ok(jwt_secret()?.into_bytes())
}

fn state_part_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn state_part_decode(value: &str) -> Result<String, String> {
    let mut out = String::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &value[i + 1..i + 3];
            let byte = u8::from_str_radix(hex, 16).map_err(|_| "Invalid OAuth state encoding")?;
            out.push(byte as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

pub fn build_oauth_state(
    provider_id: &str,
    user_id: &str,
    return_origin: &str,
    code_verifier: &str,
) -> Result<String, String> {
    let expires = DateTime::now().timestamp_millis() + 10 * 60 * 1000;
    let message = format!("{provider_id}-oauth:{user_id}:{expires}:{return_origin}:{code_verifier}");
    let sig = hmac_sha256_hex(&oauth_state_key()?, &message);
    Ok(format!(
        "{user_id}|{expires}|{}|{}|{sig}",
        state_part_encode(return_origin),
        state_part_encode(code_verifier),
    ))
}

pub fn verify_oauth_state(
    provider_id: &str,
    state: &str,
) -> Result<(ObjectId, String, String), String> {
    let (oid, origin, verifier) = verify_oauth_state_flexible(provider_id, state)?;
    Ok((oid, origin, verifier.unwrap_or_default()))
}

pub fn verify_oauth_state_flexible(
    provider_id: &str,
    state: &str,
) -> Result<(ObjectId, String, Option<String>), String> {
    if state.contains('|') {
        let parts: Vec<&str> = state.splitn(5, '|').collect();
        if parts.len() != 5 {
            return Err("Invalid OAuth state".into());
        }
        let user_id = parts[0];
        let expires: i64 = parts[1].parse().map_err(|_| "Invalid OAuth state expiry")?;
        let return_origin = state_part_decode(parts[2])?;
        let code_verifier = state_part_decode(parts[3])?;
        let sig = parts[4];
        if DateTime::now().timestamp_millis() > expires {
            return Err("OAuth state expired".into());
        }
        let message =
            format!("{provider_id}-oauth:{user_id}:{expires}:{return_origin}:{code_verifier}");
        if !verify_hmac_sha256_hex(&oauth_state_key()?, &message, sig) {
            return Err("Invalid OAuth state signature".into());
        }
        let oid = ObjectId::parse_str(user_id)
            .map_err(|_| String::from("Invalid user id in OAuth state"))?;
        return Ok((oid, return_origin, Some(code_verifier)));
    }

    verify_legacy_dot_oauth_state(provider_id, state)
}

fn verify_legacy_dot_oauth_state(
    provider_id: &str,
    state: &str,
) -> Result<(ObjectId, String, Option<String>), String> {
    if provider_id != "spotify" {
        return Err("Invalid OAuth state".into());
    }
    let frontend = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
        .trim_end_matches('/')
        .to_string();

    let parts: Vec<&str> = state.splitn(4, '.').collect();
    if parts.len() == 3 {
        let user_id = parts[0];
        let expires: i64 = parts[1].parse().map_err(|_| "Invalid OAuth state expiry")?;
        let sig = parts[2];
        if DateTime::now().timestamp_millis() > expires {
            return Err("OAuth state expired".into());
        }
        let message = format!("spotify-oauth:{user_id}:{expires}");
        if !verify_hmac_sha256_hex(&oauth_state_key()?, &message, sig) {
            return Err("Invalid OAuth state signature".into());
        }
        let oid = ObjectId::parse_str(user_id)
            .map_err(|_| String::from("Invalid user id in OAuth state"))?;
        return Ok((oid, frontend, None));
    }
    if parts.len() != 4 {
        return Err("Invalid OAuth state".into());
    }
    let user_id = parts[0];
    let expires: i64 = parts[1].parse().map_err(|_| "Invalid OAuth state expiry")?;
    let return_origin = state_part_decode(parts[2])?;
    let sig = parts[3];
    if DateTime::now().timestamp_millis() > expires {
        return Err("OAuth state expired".into());
    }
    let message = format!("spotify-oauth:{user_id}:{expires}:{return_origin}");
    if !verify_hmac_sha256_hex(&oauth_state_key()?, &message, sig) {
        return Err("Invalid OAuth state signature".into());
    }
    let oid = ObjectId::parse_str(user_id)
        .map_err(|_| String::from("Invalid user id in OAuth state"))?;
    Ok((oid, return_origin, None))
}

pub fn build_auth_url(
    def: &OAuthProviderDef,
    state: &str,
    code_challenge: Option<&str>,
) -> Result<String, String> {
    let cfg = provider_credentials(def).ok_or_else(|| {
        format!("Integracja {} nie jest skonfigurowana", def.name)
    })?;
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
        def.auth_url,
        url_encode(&cfg.client_id),
        url_encode(&cfg.redirect_uri),
        url_encode(state),
    );
    if !def.scopes.is_empty() {
        url.push_str("&scope=");
        url.push_str(&url_encode(def.scopes));
    }
    if def.use_pkce {
        let challenge = code_challenge.ok_or_else(|| "Missing PKCE challenge".to_string())?;
        url.push_str("&code_challenge_method=S256&code_challenge=");
        url.push_str(&url_encode(challenge));
    }
    for (key, value) in def.extra_auth_params {
        url.push('&');
        url.push_str(key);
        url.push('=');
        url.push_str(&url_encode(value));
    }
    Ok(url)
}

pub async fn exchange_code(
    def: &OAuthProviderDef,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<GenericTokenResponse, String> {
    let cfg = provider_credentials(def).ok_or_else(|| {
        format!("Integracja {} nie jest skonfigurowana", def.name)
    })?;
    let client = reqwest::Client::new();
    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", cfg.redirect_uri.clone()),
    ];
    if def.use_pkce {
        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier.to_string()));
        }
    }
    if !def.token_basic_auth {
        params.push(("client_id", cfg.client_id.clone()));
        if !(def.use_pkce && def.pkce_omit_client_secret) {
            params.push(("client_secret", cfg.client_secret.clone()));
        }
    }

    let mut req = client.post(def.token_url).form(&params);
    if def.use_pkce && def.pkce_omit_client_secret && code_verifier.is_none() {
        req = req.basic_auth(&cfg.client_id, Some(&cfg.client_secret));
    } else if def.token_basic_auth {
        req = req.basic_auth(&cfg.client_id, Some(&cfg.client_secret));
    }
    if def.id == "github" {
        req = req.header("Accept", "application/json");
    }
    if def.id == "reddit" {
        req = req.header("User-Agent", "KlovyChat/1.0");
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Token exchange failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Token exchange failed ({status}): {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("Invalid token response: {e} — {body}"))
}

pub async fn store_tokens(
    user_oid: ObjectId,
    provider: &str,
    access_token: &str,
    refresh_token: &str,
    expires_in: Option<i64>,
    scopes: Vec<String>,
    provider_user_id: Option<String>,
    provider_display_name: Option<String>,
) -> Result<(), String> {
    let ttl = expires_in.unwrap_or(3600).max(60);
    let expires_at = DateTime::from_millis(DateTime::now().timestamp_millis() + ttl * 1000);
    OauthToken::upsert(
        &get_db(),
        user_oid,
        provider,
        access_token,
        refresh_token,
        expires_at,
        scopes,
        provider_user_id,
        provider_display_name,
    )
    .await
    .map(|_| ())
}

pub async fn is_connected(user_oid: ObjectId, provider: &str) -> bool {
    matches!(
        OauthToken::find_by_user_provider(&get_db(), user_oid, provider).await,
        Ok(Some(_))
    )
}

pub fn connected_account_from_profile(
    provider: &str,
    account_name: String,
    profile_url: String,
) -> ConnectedAccount {
    ConnectedAccount {
        provider: provider.to_string(),
        account_name,
        profile_url,
    }
}

pub async fn refresh_access_token(
    def: &OAuthProviderDef,
    refresh_token: &str,
) -> Result<GenericTokenResponse, String> {
    let cfg = provider_credentials(def).ok_or_else(|| {
        format!("Integracja {} nie jest skonfigurowana", def.name)
    })?;
    let client = reqwest::Client::new();
    let mut params = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
    ];
    if !def.token_basic_auth {
        params.push(("client_id", cfg.client_id.clone()));
        params.push(("client_secret", cfg.client_secret.clone()));
    }
    let mut req = client.post(def.token_url).form(&params);
    if def.token_basic_auth {
        req = req.basic_auth(&cfg.client_id, Some(&cfg.client_secret));
    }
    let resp = req.send().await.map_err(|e| format!("Token refresh failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Token refresh failed ({status}): {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("Invalid token response: {e} — {body}"))
}

pub async fn ensure_access_token(
    token: &OauthToken,
    def: &OAuthProviderDef,
) -> Result<String, String> {
    let now = DateTime::now().timestamp_millis();
    let expires = token.expires_at.timestamp_millis();
    if now < expires - 30_000 {
        return token.access_token();
    }

    let refresh = token.refresh_token()?;
    let refreshed = refresh_access_token(def, &refresh).await?;
    let new_refresh = refreshed
        .refresh_token
        .as_deref()
        .unwrap_or(&refresh);
    let ttl = refreshed.expires_in.unwrap_or(3600).max(60);
    let expires_at = DateTime::from_millis(DateTime::now().timestamp_millis() + ttl * 1000);
    let id = token.id.ok_or_else(|| "Missing oauth token id".to_string())?;
    OauthToken::update_tokens(
        &get_db(),
        id,
        &refreshed.access_token,
        new_refresh,
        expires_at,
    )
    .await?;
    Ok(refreshed.access_token)
}

pub async fn revoke_provider_token(def: &OAuthProviderDef, token: &str) -> Result<(), String> {
    if !def.revoke_on_disconnect || def.revoke_url.is_empty() {
        return Ok(());
    }
    let cfg = provider_credentials(def).ok_or_else(|| {
        format!("Integracja {} nie jest skonfigurowana", def.name)
    })?;
    let client = reqwest::Client::new();
    let _ = client
        .post(def.revoke_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(&cfg.client_id, Some(&cfg.client_secret))
        .body(format!("token={}", url_encode(token)))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
