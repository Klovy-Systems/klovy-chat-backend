use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::time::Duration;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::oauth_token_model::{OauthToken, PROVIDER_SPOTIFY};
use crate::model::user_model::User;
use crate::utils::auth::jwt_auth::jwt_secret;
use crate::utils::crypto::keyed_hash::{hmac_sha256_hex, verify_hmac_sha256_hex};
use crate::utils::db::get_db;
use crate::utils::listening::broadcast::broadcast_listening_change;
use crate::utils::listening::resolve::{should_apply_report, ListeningReport};
use crate::utils::listening::serialize::listening_activity_json;
use crate::utils::ratelimit::Store;
use crate::utils::spotify::{
    activity_from_spotify, build_auth_url, ensure_access_token, exchange_code,
    generate_pkce_pair, get_active_playback, get_spotify_profile_id, is_connected, revoke_token,
    spotify_enabled, store_tokens,
};

static SPOTIFY_STATUS: Lazy<Store> = Lazy::new(|| Store::new(15, Duration::from_secs(60)));
/// Ręczne „sprawdź teraz” + tło co ~45s — kilka szybkich kliknięć OK, nadal chroni Spotify API.
static SPOTIFY_SYNC: Lazy<Store> = Lazy::new(|| Store::new(8, Duration::from_secs(60)));

const OAUTH_STATE_TTL_MS: i64 = 10 * 60 * 1000;

fn frontend_url() -> String {
    env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
}

fn allowed_return_origins() -> Vec<String> {
    let mut origins = Vec::new();
    if crate::utils::app_env::is_development() {
        origins.push("http://127.0.0.1:5173".to_string());
    }
    for key in ["FRONTEND_URL", "ORIGIN"] {
        if let Ok(value) = env::var(key) {
            origins.push(value.trim_end_matches('/').to_string());
        }
    }
    origins.sort();
    origins.dedup();
    origins
}

fn normalize_return_origin(return_to: Option<&str>) -> String {
    let fallback = frontend_url().trim_end_matches('/').to_string();
    let Some(raw) = return_to.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback;
    };
    let normalized = raw.trim_end_matches('/');
    if allowed_return_origins()
        .iter()
        .any(|allowed| allowed == normalized)
    {
        normalized.to_string()
    } else {
        fallback
    }
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
    url_decode(value)
}

fn build_oauth_state(user_id: &str, return_origin: &str, code_verifier: &str) -> Result<String, String> {
    let expires = DateTime::now().timestamp_millis() + OAUTH_STATE_TTL_MS;
    let message = format!("spotify-oauth:{user_id}:{expires}:{return_origin}:{code_verifier}");
    let sig = hmac_sha256_hex(&oauth_state_key()?, &message);
    Ok(format!(
        "{user_id}|{expires}|{}|{}|{sig}",
        state_part_encode(return_origin),
        state_part_encode(code_verifier),
    ))
}

fn verify_pipe_oauth_state(state: &str) -> Result<(ObjectId, String, Option<String>), String> {
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
    let message = format!("spotify-oauth:{user_id}:{expires}:{return_origin}:{code_verifier}");
    if !verify_hmac_sha256_hex(&oauth_state_key()?, &message, sig) {
        return Err("Invalid OAuth state signature".into());
    }
    let oid = ObjectId::parse_str(user_id)
        .map_err(|_| String::from("Invalid user id in OAuth state"))?;
    Ok((oid, return_origin, Some(code_verifier)))
}

fn verify_legacy_dot_oauth_state(state: &str) -> Result<(ObjectId, String, Option<String>), String> {
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
        return Ok((oid, frontend_url().trim_end_matches('/').to_string(), None));
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

fn verify_oauth_state(state: &str) -> Result<(ObjectId, String, Option<String>), String> {
    if state.contains('|') {
        verify_pipe_oauth_state(state)
    } else {
        verify_legacy_dot_oauth_state(state)
    }
}

async fn load_active_user(user_id: &str) -> Result<User, HttpResponse> {
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return Err(HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" })));
    };
    let db = get_db();
    match User::find_by_id(&db, oid).await {
        Ok(Some(user)) if user.is_login_allowed() && !user.is_bot => {
            Ok(user)
        }
        Ok(Some(_)) => Err(HttpResponse::Forbidden().json(json!({ "error": "Forbidden" }))),
        Ok(None) => Err(HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }))),
        Err(_) => Err(HttpResponse::InternalServerError().json(json!({ "error": "Server error" }))),
    }
}

pub async fn spotify_status(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    if !SPOTIFY_STATUS.check_and_increment_with_window(
        &format!("spotify-status:{user_id}"),
        15,
        Duration::from_secs(60),
    ) {
        return HttpResponse::TooManyRequests().json(json!({ "error": "Rate limit exceeded" }));
    }
    let Ok(user) = load_active_user(&user_id).await else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Some(oid) = user.id else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };
    let connected = is_connected(oid).await;
    HttpResponse::Ok().json(json!({
        "connected": connected,
        "shareListening": user.share_listening,
        "enabled": spotify_enabled(),
    }))
}

pub async fn spotify_connect(req: HttpRequest, query: web::Query<SpotifyConnectQuery>) -> HttpResponse {
    if !spotify_enabled() {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Spotify integration is not configured" }));
    }
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    if load_active_user(&user_id).await.is_err() {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    }

    let return_origin = normalize_return_origin(query.return_to.as_deref());
    let (code_verifier, code_challenge) = generate_pkce_pair();
    let state = match build_oauth_state(&user_id, &return_origin, &code_verifier) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),
    };
    let url = match build_auth_url(&state, &code_challenge) {
        Ok(u) => u,
        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),
    };
    HttpResponse::Found()
        .append_header(("Location", url))
        .finish()
}

pub async fn spotify_connect_url(
    req: HttpRequest,
    query: web::Query<SpotifyConnectQuery>,
) -> HttpResponse {
    if !spotify_enabled() {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Spotify integration is not configured" }));
    }
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    if load_active_user(&user_id).await.is_err() {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    }

    let return_origin = normalize_return_origin(query.return_to.as_deref());
    let (code_verifier, code_challenge) = generate_pkce_pair();
    let state = match build_oauth_state(&user_id, &return_origin, &code_verifier) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),
    };
    let url = match build_auth_url(&state, &code_challenge) {
        Ok(u) => u,
        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),
    };
    HttpResponse::Ok().json(json!({ "url": url }))
}

const SPOTIFY_REAUTH_HINT: &str = "Spotify już zatwierdziło tę aplikację, ale Klovy nie ma zapisanego tokenu. Wejdź na https://www.spotify.com/account/apps/, usuń aplikację Klovy i połącz ponownie.";

async fn resolve_spotify_refresh_token(
    user_oid: ObjectId,
    tokens: &crate::utils::spotify::TokenResponse,
) -> Result<String, String> {
    if let Some(refresh) = tokens.refresh_token.clone() {
        return Ok(refresh);
    }

    match OauthToken::find_by_user_provider(&get_db(), user_oid, PROVIDER_SPOTIFY).await {
        Ok(Some(existing)) => existing.refresh_token(),
        Ok(None) => Err(SPOTIFY_REAUTH_HINT.to_string()),
        Err(e) => {
            log::error!("Spotify refresh lookup failed for {user_oid}: {e}");
            Err(SPOTIFY_REAUTH_HINT.to_string())
        }
    }
}

fn map_spotify_oauth_error(error: &str, description: &str) -> String {
    let base = match error {
        "access_denied" => "Odmowa dostępu Spotify. W trybie Development dodaj swój adres e-mail konta Spotify w Spotify Developer Dashboard → User Management → Add user.".to_string(),
        "invalid_scope" => "Nieprawidłowy zakres uprawnień Spotify.".to_string(),
        "server_error" => "Błąd serwera Spotify. Spróbuj ponownie za chwilę i zaloguj się bezpośrednio e-mailem Spotify (nie przez Google/Facebook/Apple).".to_string(),
        other => format!("Błąd Spotify: {other}"),
    };
    if description.is_empty() {
        base
    } else {
        format!("{base} ({description})")
    }
}

pub async fn spotify_callback(query: web::Query<SpotifyCallbackQuery>) -> HttpResponse {
    let fail = |frontend: &str, msg: &str| {
        HttpResponse::Found()
            .append_header((
                "Location",
                format!("{frontend}/?spotify=error&message={}", url_encode(msg)),
            ))
            .finish()
    };
    let succeed = |frontend: &str| {
        HttpResponse::Found()
            .append_header(("Location", format!("{frontend}/?spotify=connected")))
            .finish()
    };

    if !spotify_enabled() {
        return fail(
            &frontend_url().trim_end_matches('/'),
            "Integracja Spotify nie jest skonfigurowana",
        );
    }

    if let Some(err) = &query.error {
        let desc = query.error_description.as_deref().unwrap_or("");
        log::warn!("Spotify OAuth callback error: {err} — {desc}");
        return fail(
            &frontend_url().trim_end_matches('/'),
            &map_spotify_oauth_error(err, desc),
        );
    }

    let Some(code) = query.code.as_deref() else {
        return fail(
            &frontend_url().trim_end_matches('/'),
            "Brak kodu autoryzacji",
        );
    };
    let Some(state) = query.state.as_deref() else {
        return fail(
            &frontend_url().trim_end_matches('/'),
            "Brak stanu OAuth",
        );
    };

    let (user_oid, return_origin, code_verifier) = match verify_oauth_state(state) {
        Ok(result) => result,
        Err(e) => return fail(&frontend_url().trim_end_matches('/'), &e),
    };

    let tokens = match exchange_code(code, code_verifier.as_deref()).await {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Spotify token exchange failed: {e}");
            let friendly = if e.contains("invalid_grant") {
                "Kod autoryzacji wygasł lub redirect URI nie zgadza się z Spotify Dashboard. Upewnij się, że Redirect URI to dokładnie: ".to_string()
                    + &crate::utils::spotify::resolve_redirect_uri().unwrap_or_default()
            } else {
                e
            };
            return fail(&return_origin, &friendly);
        }
    };
    let refresh = match resolve_spotify_refresh_token(user_oid, &tokens).await {
        Ok(r) => r,
        Err(e) => return fail(&return_origin, &e),
    };

    let profile_id = get_spotify_profile_id(&tokens.access_token)
        .await
        .ok()
        .flatten();

    if let Err(e) = store_tokens(
        user_oid,
        &tokens.access_token,
        &refresh,
        tokens.expires_in,
        profile_id,
    )
    .await
    {
        log::error!("Spotify store_tokens failed for {user_oid}: {e}");
        return fail(
            &return_origin,
            "Nie udało się zapisać połączenia Spotify. Spróbuj połączyć ponownie.",
        );
    }

    log::info!("Spotify connected for user {user_oid}");
    succeed(&return_origin)
}

#[derive(Deserialize)]
pub struct SpotifyConnectQuery {
    #[serde(rename = "returnTo")]
    pub return_to: Option<String>,
}

#[derive(Deserialize)]
pub struct SpotifyCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "error_description")]
    pub error_description: Option<String>,
}

#[derive(Deserialize)]
pub struct SpotifySyncBody {
    #[serde(rename = "clientType", default = "default_client_type")]
    pub client_type: String,
    #[serde(rename = "clientInstanceId")]
    pub client_instance_id: String,
}

fn default_client_type() -> String {
    "web".to_string()
}

fn url_encode(value: &str) -> String {
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

fn url_decode(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| "Invalid OAuth return origin".to_string())?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| "Invalid OAuth return origin".to_string())?;
            out.push(byte as char);
            i += 3;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

pub async fn spotify_sync(req: HttpRequest, body: web::Json<SpotifySyncBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    if !SPOTIFY_SYNC.check_and_increment(&format!("spotify-sync:{user_id}")) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "retryAfter": 15,
        }));
    }

    let Ok(user) = load_active_user(&user_id).await else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Some(oid) = user.id else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };

    if body.client_instance_id.trim().is_empty() || body.client_instance_id.len() > 128 {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid clientInstanceId" }));
    }
    let client_type = match body.client_type.as_str() {
        "web" | "desktop" => body.client_type.clone(),
        _ => return HttpResponse::BadRequest().json(json!({ "error": "Invalid clientType" })),
    };

    if !user.share_listening {
        if user.listening_activity.is_some() {
            let _ = User::set_fields(
                &get_db(),
                oid,
                doc! { "listeningActivity": Bson::Null },
            )
            .await;
            if let Ok(Some(updated)) = User::find_by_id(&get_db(), oid).await {
                broadcast_listening_change(&user_id, &updated).await;
            }
        }
        return HttpResponse::Ok().json(json!({
            "listeningActivity": null,
            "shareListening": false,
        }));
    }

    let Some(token_doc) = OauthToken::find_by_user_provider(&get_db(), oid, PROVIDER_SPOTIFY)
        .await
        .ok()
        .flatten()
    else {
        return HttpResponse::BadRequest().json(json!({ "error": "Spotify not connected" }));
    };

    let access = match ensure_access_token(&token_doc).await {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::BadGateway().json(json!({ "error": e }));
        }
    };

    let playing = match get_active_playback(&access).await {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadGateway().json(json!({ "error": e })),
    };

    let new_activity = playing
        .as_ref()
        .and_then(|p| activity_from_spotify(p, &client_type, &body.client_instance_id));

    let report = ListeningReport {
        activity: new_activity,
        client_type: client_type.clone(),
        client_instance_id: body.client_instance_id.clone(),
    };

    if !should_apply_report(&user.listening_activity, &report) {
        let current = user
            .listening_activity
            .as_ref()
            .filter(|a| a.is_playing)
            .map(listening_activity_json);
        return HttpResponse::Ok().json(json!({
            "listeningActivity": current,
            "shareListening": user.share_listening,
            "applied": false,
        }));
    }

    let set_doc = if let Some(activity) = report.activity {
        let bson = mongodb::bson::to_bson(&activity).unwrap_or(Bson::Null);
        doc! { "listeningActivity": bson }
    } else {
        doc! { "listeningActivity": Bson::Null }
    };

    let updated = match User::set_fields(&get_db(), oid, set_doc).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    broadcast_listening_change(&user_id, &updated).await;

    let listening = updated
        .listening_activity
        .as_ref()
        .filter(|a| a.is_playing)
        .map(listening_activity_json);

    HttpResponse::Ok().json(json!({
        "listeningActivity": listening,
        "shareListening": updated.share_listening,
        "applied": true,
    }))
}

pub async fn spotify_disconnect(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Ok(user) = load_active_user(&user_id).await else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Some(oid) = user.id else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };
    let db = get_db();

    if let Ok(Some(token_doc)) = OauthToken::find_by_user_provider(&db, oid, PROVIDER_SPOTIFY).await
    {
        if let Ok(access) = token_doc.access_token() {
            let _ = revoke_token(&access).await;
        }
        let _ = OauthToken::delete_for_user_provider(&db, oid, PROVIDER_SPOTIFY).await;
    }

    let updated = match User::set_fields(
        &db,
        oid,
        doc! { "listeningActivity": Bson::Null },
    )
    .await
    {
        Ok(Some(u)) => u,
        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    broadcast_listening_change(&user_id, &updated).await;

    HttpResponse::Ok().json(json!({ "success": true, "connected": false }))
}

#[derive(Deserialize)]
pub struct ListeningSettingsBody {
    #[serde(rename = "shareListening")]
    pub share_listening: bool,
}

pub async fn update_listening_settings(
    req: HttpRequest,
    body: web::Json<ListeningSettingsBody>,
) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Ok(user) = load_active_user(&user_id).await else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Some(oid) = user.id else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };

    let mut set = doc! { "shareListening": body.share_listening };
    if !body.share_listening {
        set.insert("listeningActivity", Bson::Null);
    }

    let updated = match User::set_fields(&get_db(), oid, set).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    if !body.share_listening {
        broadcast_listening_change(&user_id, &updated).await;
    }

    HttpResponse::Ok().json(json!({
        "success": true,
        "shareListening": updated.share_listening,
    }))
}
