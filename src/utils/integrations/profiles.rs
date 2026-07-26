use serde::Deserialize;

use crate::model::user_model::ConnectedAccount;

use super::oauth::{connected_account_from_profile, provider_credentials, GenericTokenResponse};
use super::providers::OAuthProviderDef;

pub struct ProfileFetchResult {
    pub account: ConnectedAccount,
    pub provider_user_id: Option<String>,
    pub provider_display_name: Option<String>,
}

pub async fn fetch_provider_profile(
    def: &OAuthProviderDef,
    access_token: &str,
    tokens: &GenericTokenResponse,
) -> Result<ProfileFetchResult, String> {
    match def.id {
        "github" => fetch_github(def.id, access_token).await,
        "twitch" => fetch_twitch(def, access_token).await,
        "reddit" => fetch_reddit(def.id, access_token).await,
        "twitter" => fetch_twitter(def.id, access_token).await,
        "youtube" => fetch_youtube(access_token).await,
        "spotify" => fetch_spotify(def.id, access_token).await,
        "tiktok" => fetch_tiktok(def, access_token).await,
        "epic" => fetch_epic(def.id, access_token, tokens).await,
        "paypal" => fetch_paypal(access_token).await,
        "riot" => fetch_riot(access_token).await,
        "ebay" => fetch_ebay(access_token).await,
        "xbox" => fetch_xbox(def.id, access_token).await,
        other => Err(format!("Profile fetch not implemented for {other}")),
    }
}

async fn http_get_json(url: &str, access_token: &str, extra_headers: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let mut req = client
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Profile request failed ({status}): {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("Invalid profile JSON: {e}"))
}

async fn fetch_github(provider: &str, access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json("https://api.github.com/user", access_token, &[]).await?;
    let login = json["login"].as_str().unwrap_or("GitHub").to_string();
    let url = json["html_url"]
        .as_str()
        .unwrap_or("https://github.com")
        .to_string();
    let id = json.get("id").map(|v| v.to_string());
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(provider, login.clone(), url),
        provider_user_id: id,
        provider_display_name: Some(login),
    })
}

async fn fetch_twitch(def: &OAuthProviderDef, access_token: &str) -> Result<ProfileFetchResult, String> {
    let cfg = provider_credentials(def).ok_or_else(|| "Twitch not configured".to_string())?;
    let json = http_get_json(
        "https://api.twitch.tv/helix/users",
        access_token,
        &[("Client-Id", cfg.client_id.as_str())],
    )
    .await?;
    let user = json["data"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| "Empty Twitch profile".to_string())?;
    let login = user["login"].as_str().unwrap_or("Twitch").to_string();
    let display = user["display_name"].as_str().unwrap_or(&login).to_string();
    let id = user["id"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            def.id,
            display.clone(),
            format!("https://twitch.tv/{login}"),
        ),
        provider_user_id: id,
        provider_display_name: Some(display),
    })
}

async fn fetch_reddit(provider: &str, access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://oauth.reddit.com/api/v1/me",
        access_token,
        &[("User-Agent", "KlovyChat/1.0")],
    )
    .await?;
    let name = json["name"].as_str().unwrap_or("Reddit").to_string();
    let id = json["id"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            provider,
            format!("u/{name}"),
            format!("https://reddit.com/user/{name}"),
        ),
        provider_user_id: id,
        provider_display_name: Some(name),
    })
}

async fn fetch_twitter(provider: &str, access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://api.twitter.com/2/users/me?user.fields=username,name",
        access_token,
        &[],
    )
    .await?;
    let user = &json["data"];
    let username = user["username"].as_str().unwrap_or("user").to_string();
    let name = user["name"].as_str().unwrap_or(&username).to_string();
    let id = user["id"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            provider,
            format!("@{username}"),
            format!("https://x.com/{username}"),
        ),
        provider_user_id: id,
        provider_display_name: Some(name),
    })
}

async fn fetch_spotify(provider: &str, access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json("https://api.spotify.com/v1/me", access_token, &[]).await?;
    let id = json["id"].as_str().unwrap_or_default().to_string();
    let name = json["display_name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "Spotify".to_string());
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            provider,
            name.clone(),
            format!("https://open.spotify.com/user/{id}"),
        ),
        provider_user_id: if id.is_empty() { None } else { Some(id) },
        provider_display_name: Some(name),
    })
}

async fn fetch_youtube(access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true",
        access_token,
        &[],
    )
    .await?;
    let channel = json["items"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| "Brak kanału YouTube na tym koncie Google".to_string())?;
    let title = channel["snippet"]["title"]
        .as_str()
        .unwrap_or("YouTube")
        .to_string();
    let channel_id = channel["id"].as_str().unwrap_or("");
    let id = if channel_id.is_empty() {
        None
    } else {
        Some(channel_id.to_string())
    };
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            "youtube",
            title.clone(),
            format!("https://www.youtube.com/channel/{channel_id}"),
        ),
        provider_user_id: id,
        provider_display_name: Some(title),
    })
}

#[derive(Deserialize)]
struct TikTokUserData {
    user: TikTokUser,
}

#[derive(Deserialize)]
struct TikTokUser {
    display_name: Option<String>,
    username: Option<String>,
    profile_deep_link: Option<String>,
    open_id: Option<String>,
}

async fn fetch_tiktok(def: &OAuthProviderDef, access_token: &str) -> Result<ProfileFetchResult, String> {
    let _ = provider_credentials(def).ok_or_else(|| "TikTok not configured".to_string())?;
    let client = reqwest::Client::new();
    let resp = client
        .get("https://open.tiktokapis.com/v2/user/info/?fields=open_id,username,display_name,profile_deep_link")
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let parsed: TikTokUserData = serde_json::from_str(&body)
        .map_err(|e| format!("Invalid TikTok profile: {e} — {body}"))?;
    let username = parsed.user.username.clone();
    let name = parsed
        .user
        .display_name
        .or(username.clone())
        .unwrap_or_else(|| "TikTok".to_string());
    let url = parsed
        .user
        .profile_deep_link
        .unwrap_or_else(|| format!("https://www.tiktok.com/@{}", username.unwrap_or_default()));
    Ok(ProfileFetchResult {
        account: connected_account_from_profile("tiktok", name.clone(), url),
        provider_user_id: parsed.user.open_id,
        provider_display_name: Some(name),
    })
}

async fn fetch_epic(
    provider: &str,
    access_token: &str,
    tokens: &GenericTokenResponse,
) -> Result<ProfileFetchResult, String> {
    #[derive(Deserialize)]
    struct EpicAccount {
        #[serde(rename = "displayName")]
        display_name: Option<String>,
        id: Option<String>,
    }
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.epicgames.dev/epic/id/v2/accounts")
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if let Ok(list) = serde_json::from_str::<Vec<EpicAccount>>(&body) {
        if let Some(acc) = list.first() {
            let name = acc.display_name.clone().unwrap_or_else(|| "Epic".to_string());
            let id = acc.id.clone();
            return Ok(ProfileFetchResult {
                account: connected_account_from_profile(
                    provider,
                    name.clone(),
                    "https://store.epicgames.com/".to_string(),
                ),
                provider_user_id: id,
                provider_display_name: Some(name),
            });
        }
    }
    let name = tokens
        .token_type
        .clone()
        .unwrap_or_else(|| "Epic Games".to_string());
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            provider,
            name.clone(),
            "https://store.epicgames.com/".to_string(),
        ),
        provider_user_id: None,
        provider_display_name: Some(name),
    })
}

async fn fetch_paypal(access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1",
        access_token,
        &[],
    )
    .await?;
    let name = json["name"]
        .as_str()
        .or_else(|| json["preferred_username"].as_str())
        .unwrap_or("PayPal")
        .to_string();
    let id = json["user_id"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile("paypal", name.clone(), "https://www.paypal.com/".to_string()),
        provider_user_id: id,
        provider_display_name: Some(name),
    })
}

async fn fetch_riot(access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://europe.api.riotgames.com/riot/account/v1/accounts/me",
        access_token,
        &[],
    )
    .await?;
    let game_name = json["gameName"].as_str().unwrap_or("Riot");
    let tag = json["tagLine"].as_str().unwrap_or("");
    let name = if tag.is_empty() {
        game_name.to_string()
    } else {
        format!("{game_name}#{tag}")
    };
    let puuid = json["puuid"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            "riot",
            name.clone(),
            "https://account.riotgames.com/".to_string(),
        ),
        provider_user_id: puuid,
        provider_display_name: Some(name),
    })
}

async fn fetch_ebay(access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json(
        "https://apiz.ebay.com/commerce/identity/v1/user/",
        access_token,
        &[],
    )
    .await?;
    let username = json["username"].as_str().unwrap_or("eBay").to_string();
    let id = json["userId"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            "ebay",
            username.clone(),
            format!("https://www.ebay.com/usr/{username}"),
        ),
        provider_user_id: id,
        provider_display_name: Some(username),
    })
}

async fn fetch_xbox(provider: &str, access_token: &str) -> Result<ProfileFetchResult, String> {
    let json = http_get_json("https://graph.microsoft.com/v1.0/me", access_token, &[]).await?;
    let name = json["displayName"]
        .as_str()
        .or_else(|| json["userPrincipalName"].as_str())
        .unwrap_or("Xbox")
        .to_string();
    let id = json["id"].as_str().map(str::to_string);
    Ok(ProfileFetchResult {
        account: connected_account_from_profile(
            provider,
            name.clone(),
            "https://www.xbox.com/".to_string(),
        ),
        provider_user_id: id,
        provider_display_name: Some(name),
    })
}
