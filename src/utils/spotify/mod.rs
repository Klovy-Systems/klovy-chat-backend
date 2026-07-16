use mongodb::bson::DateTime;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;

use crate::model::oauth_token_model::{OauthToken, PROVIDER_SPOTIFY};
use crate::model::user_model::ListeningActivity;
use crate::utils::db::get_db;

pub const SPOTIFY_SCOPES: &str = "user-read-currently-playing user-read-playback-state";

#[derive(Debug, Clone)]
pub struct SpotifyConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub fn spotify_config() -> Option<SpotifyConfig> {
    let client_id = env::var("SPOTIFY_CLIENT_ID").ok()?;
    let client_secret = env::var("SPOTIFY_CLIENT_SECRET").ok()?;
    let redirect_uri = resolve_redirect_uri()?;
    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return None;
    }
    Some(SpotifyConfig {
        client_id: client_id.trim().to_string(),
        client_secret: client_secret.trim().to_string(),
        redirect_uri,
    })
}

/// Redirect URI musi dokładnie odpowiadać wpisowi w Spotify Dashboard.
/// W dev najlepiej przez frontend (Vite proxy), np. http://127.0.0.1:5173/api/integrations/spotify/callback
pub fn resolve_redirect_uri() -> Option<String> {
    let explicit = env::var("SPOTIFY_REDIRECT_URI").ok();
    let uri = if let Some(raw) = explicit {
        if raw.trim().is_empty() {
            None
        } else {
            Some(raw.trim().to_string())
        }
    } else {
        env::var("FRONTEND_URL")
            .ok()
            .map(|f| format!("{}/api/integrations/spotify/callback", f.trim().trim_end_matches('/')))
    }?;
    Some(normalize_redirect_uri(&uri))
}

/// Spotify Developer Dashboard często wymaga 127.0.0.1.
fn normalize_redirect_uri(uri: &str) -> String {
    uri.replace("://localhost", "://127.0.0.1")
}

pub fn spotify_enabled() -> bool {
    spotify_config().is_some()
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

fn base64_url_encode_no_pad(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
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

/// PKCE — wymagane przez Spotify dla nowych aplikacji (od 2025).
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

pub fn build_auth_url(state: &str, code_challenge: &str) -> Result<String, String> {
    let cfg = spotify_config().ok_or_else(|| "Spotify integration is not configured".to_string())?;
    Ok(format!(
        "https://accounts.spotify.com/authorize?response_type=code&client_id={}&scope={}&redirect_uri={}&state={}&code_challenge_method=S256&code_challenge={}&show_dialog=true",
        url_encode(&cfg.client_id),
        url_encode(SPOTIFY_SCOPES),
        url_encode(&cfg.redirect_uri),
        url_encode(state),
        url_encode(code_challenge),
    ))
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
}

pub async fn exchange_code(code: &str, code_verifier: Option<&str>) -> Result<TokenResponse, String> {
    let cfg = spotify_config().ok_or_else(|| "Spotify integration is not configured".to_string())?;
    let client = reqwest::Client::new();

    let body = if let Some(verifier) = code_verifier {
        format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            url_encode(code),
            url_encode(&cfg.redirect_uri),
            url_encode(&cfg.client_id),
            url_encode(verifier),
        )
    } else {
        format!(
            "grant_type=authorization_code&code={}&redirect_uri={}",
            url_encode(code),
            url_encode(&cfg.redirect_uri),
        )
    };

    let mut req = client
        .post("https://accounts.spotify.com/api/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body);

    if code_verifier.is_none() {
        req = req.basic_auth(&cfg.client_id, Some(&cfg.client_secret));
    }

    let res = req.send().await.map_err(|e| e.to_string())?;

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(format!("Spotify token exchange failed: {body}"));
    }

    res.json::<TokenResponse>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn refresh_access_token(refresh_token: &str) -> Result<TokenResponse, String> {
    let cfg = spotify_config().ok_or_else(|| "Spotify integration is not configured".to_string())?;
    let client = reqwest::Client::new();
    let res = client
        .post("https://accounts.spotify.com/api/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(&cfg.client_id, Some(&cfg.client_secret))
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            url_encode(refresh_token),
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(format!("Spotify token refresh failed: {body}"));
    }

    res.json::<TokenResponse>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn revoke_token(token: &str) -> Result<(), String> {
    let cfg = spotify_config().ok_or_else(|| "Spotify integration is not configured".to_string())?;
    let client = reqwest::Client::new();
    let _ = client
        .post("https://accounts.spotify.com/api/token/revoke")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(&cfg.client_id, Some(&cfg.client_secret))
        .body(format!("token={}", url_encode(token)))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SpotifyArtist {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SpotifyImage {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SpotifyAlbum {
    images: Option<Vec<SpotifyImage>>,
}

#[derive(Debug, Deserialize)]
struct SpotifyExternalUrls {
    spotify: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SpotifyTrack {
    name: String,
    artists: Vec<SpotifyArtist>,
    album: SpotifyAlbum,
    external_urls: SpotifyExternalUrls,
}

#[derive(Debug, Deserialize)]
pub struct CurrentlyPlayingResponse {
    is_playing: bool,
    item: Option<SpotifyTrack>,
}

pub async fn get_currently_playing(access_token: &str) -> Result<Option<CurrentlyPlayingResponse>, String> {
    fetch_player_endpoint(access_token, "https://api.spotify.com/v1/me/player/currently-playing").await
}

async fn get_playback_state(access_token: &str) -> Result<Option<CurrentlyPlayingResponse>, String> {
    fetch_player_endpoint(access_token, "https://api.spotify.com/v1/me/player").await
}

async fn fetch_player_endpoint(
    access_token: &str,
    url: &str,
) -> Result<Option<CurrentlyPlayingResponse>, String> {
    let client = reqwest::Client::new();
    let res = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(map_spotify_player_error(&body));
    }

    res.json::<CurrentlyPlayingResponse>()
        .await
        .map_err(|e| e.to_string())
        .map(Some)
}

pub fn map_spotify_player_error(body: &str) -> String {
    let lower = body.to_lowercase();
    if lower.contains("active premium subscription required for the owner of the app") {
        return "Spotify wymaga konta Premium u właściciela aplikacji w Spotify Developer Dashboard (tryb Development). Zaloguj się na to konto w Spotify, wykup Premium i odczekaj do kilku godzin. Szczegóły: https://developer.spotify.com/documentation/web-api/concepts/quota-modes".to_string();
    }
    if lower.contains("premium") && lower.contains("required") {
        return "Spotify wymaga konta Premium do odczytu aktualnie odtwarzanego utworu.".to_string();
    }
    format!("Spotify player request failed: {body}")
}

/// Najpierw currently-playing, potem pełny stan playera (lepsze dla Spotify Web).
pub async fn get_active_playback(access_token: &str) -> Result<Option<CurrentlyPlayingResponse>, String> {
    if let Some(cp) = get_currently_playing(access_token).await? {
        if cp.is_playing && cp.item.is_some() {
            return Ok(Some(cp));
        }
    }
    get_playback_state(access_token).await
}

pub async fn get_spotify_profile_id(access_token: &str) -> Result<Option<String>, String> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://api.spotify.com/v1/me")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !res.status().is_success() {
        return Ok(None);
    }

    #[derive(Deserialize)]
    struct Me {
        id: String,
    }

    let me = res.json::<Me>().await.map_err(|e| e.to_string())?;
    Ok(Some(me.id))
}

fn expires_at_from_secs(secs: i64) -> DateTime {
    let now_ms = DateTime::now().timestamp_millis();
    DateTime::from_millis(now_ms + secs * 1000)
}

pub async fn ensure_access_token(token: &OauthToken) -> Result<String, String> {
    let now = DateTime::now().timestamp_millis();
    let expires = token.expires_at.timestamp_millis();
    if now < expires - 30_000 {
        return token.access_token();
    }

    let refresh = token.refresh_token()?;
    let refreshed = refresh_access_token(&refresh).await?;
    let new_refresh = refreshed
        .refresh_token
        .as_deref()
        .unwrap_or(&refresh);
    let expires_at = expires_at_from_secs(refreshed.expires_in);
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

pub fn activity_from_spotify(
    response: &CurrentlyPlayingResponse,
    client_type: &str,
    client_instance_id: &str,
) -> Option<ListeningActivity> {
    if !response.is_playing {
        return None;
    }
    let track = response.item.as_ref()?;
    let artist = track
        .artists
        .iter()
        .map(|a| a.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let artist = if artist.is_empty() { None } else { Some(artist) };
    let album_art = track
        .album
        .images
        .as_ref()
        .and_then(|imgs| imgs.first())
        .map(|i| i.url.clone());
    let external_url = track.external_urls.spotify.clone();

    Some(ListeningActivity {
        platform: "spotify".to_string(),
        track_title: track.name.clone(),
        artist,
        album_art,
        external_url,
        is_playing: true,
        updated_at: DateTime::now(),
        source: "oauth_api".to_string(),
        client_type: client_type.to_string(),
        client_instance_id: client_instance_id.to_string(),
    })
}

pub async fn store_tokens(
    user_id: mongodb::bson::oid::ObjectId,
    access_token: &str,
    refresh_token: &str,
    expires_in: i64,
    provider_user_id: Option<String>,
) -> Result<OauthToken, String> {
    let expires_at = expires_at_from_secs(expires_in);
    OauthToken::upsert(
        &get_db(),
        user_id,
        PROVIDER_SPOTIFY,
        access_token,
        refresh_token,
        expires_at,
        SPOTIFY_SCOPES.split_whitespace().map(String::from).collect(),
        provider_user_id,
    )
    .await
}

pub async fn is_connected(user_id: mongodb::bson::oid::ObjectId) -> bool {
    match OauthToken::find_by_user_provider(&get_db(), user_id, PROVIDER_SPOTIFY).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            log::error!("Spotify is_connected lookup failed for {user_id}: {e}");
            false
        }
    }
}
