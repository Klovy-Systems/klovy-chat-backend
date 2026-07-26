use mongodb::bson::DateTime;
use serde::Deserialize;

use crate::model::user_model::ListeningActivity;

use super::providers::OAuthProviderDef;

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
struct SpotifyDevice {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SpotifyExternalUrls {
    spotify: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpotifyTrack {
    name: String,
    artists: Vec<SpotifyArtist>,
    album: SpotifyAlbum,
    external_urls: SpotifyExternalUrls,
}

#[derive(Debug, Deserialize)]
pub struct CurrentlyPlayingResponse {
    is_playing: bool,
    item: Option<SpotifyTrack>,
    device: Option<SpotifyDevice>,
}

fn is_desktop_app_playback(response: &CurrentlyPlayingResponse) -> bool {
    let Some(device) = &response.device else {
        return true;
    };
    let name = device.name.to_lowercase();
    !name.contains("web player") && !name.contains("webplayer")
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
        return Err(map_player_error(&body));
    }

    res.json::<CurrentlyPlayingResponse>()
        .await
        .map_err(|e| e.to_string())
        .map(Some)
}

fn map_player_error(body: &str) -> String {
    let lower = body.to_lowercase();
    if lower.contains("active premium subscription required for the owner of the app") {
        return "Spotify wymaga konta Premium u właściciela aplikacji w Spotify Developer Dashboard (tryb Development). Zaloguj się na to konto w Spotify, wykup Premium i odczekaj do kilku godzin. Szczegóły: https://developer.spotify.com/documentation/web-api/concepts/quota-modes".to_string();
    }
    if lower.contains("premium") && lower.contains("required") {
        return "Spotify wymaga konta Premium do odczytu aktualnie odtwarzanego utworu.".to_string();
    }
    format!("Spotify player request failed: {body}")
}

async fn get_active_playback(access_token: &str) -> Result<Option<CurrentlyPlayingResponse>, String> {
    if let Some(cp) = fetch_player_endpoint(
        access_token,
        "https://api.spotify.com/v1/me/player/currently-playing",
    )
    .await?
    {
        if cp.is_playing && cp.item.is_some() {
            return Ok(Some(cp));
        }
    }
    fetch_player_endpoint(access_token, "https://api.spotify.com/v1/me/player").await
}

fn activity_from_playback(
    response: &CurrentlyPlayingResponse,
    client_type: &str,
    client_instance_id: &str,
    platform: &str,
) -> Option<ListeningActivity> {
    if !response.is_playing || !is_desktop_app_playback(response) {
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
        platform: platform.to_string(),
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

pub async fn fetch_active_listening_activity(
    def: &OAuthProviderDef,
    access_token: &str,
    client_type: &str,
    client_instance_id: &str,
) -> Result<Option<ListeningActivity>, String> {
    match def.id {
        "spotify" => {
            let playing = get_active_playback(access_token).await?;
            Ok(playing
                .as_ref()
                .and_then(|p| activity_from_playback(p, client_type, client_instance_id, def.id)))
        }
        other => Err(format!("Listening sync not implemented for {other}")),
    }
}

pub fn map_oauth_error(provider_id: &str, error: &str, description: &str) -> String {
    if provider_id != "spotify" {
        return format!("Odmowa autoryzacji ({error})");
    }
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

pub const SPOTIFY_REAUTH_HINT: &str = "Spotify już zatwierdziło tę aplikację, ale Klovy nie ma zapisanego tokenu. Wejdź na https://www.spotify.com/account/apps/, usuń aplikację Klovy i połącz ponownie.";

pub fn map_token_exchange_error(def: &OAuthProviderDef, error: &str) -> String {
    if def.id != "spotify" {
        return error.to_string();
    }
    if error.contains("invalid_grant") {
        let redirect = super::oauth::resolve_redirect_uri(def).unwrap_or_default();
        return format!(
            "Kod autoryzacji wygasł lub redirect URI nie zgadza się z Spotify Dashboard. Upewnij się, że Redirect URI to dokładnie: {redirect}"
        );
    }
    error.to_string()
}
