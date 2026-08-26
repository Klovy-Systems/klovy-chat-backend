// emojis.rs
// Proxy listy emoji (klucz zewnętrzny zostaje na serwerze).
// Zakres:
//  - 502 gdy upstream padnie
//  - proxy listy; 502 gdy upstream padnie, bez site key na FE
// Nie serwuj site key Giphy na FE.
// Przy zmianach: api/emojis.ts, security/urls.rs.

use actix_web::HttpResponse;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Clone)]
struct EmojiDataset {
    count: usize,
    groups: Value,
}

static EMOJI_CACHE: Lazy<Mutex<Option<EmojiDataset>>> = Lazy::new(|| Mutex::new(None));

#[derive(Deserialize)]
struct RawEmoji {
    emoji: String,
    name: String,
    slug: String,
}

#[derive(Deserialize)]
struct RawGroup {
    name: String,
    slug: String,
    emojis: Vec<RawEmoji>,
}

fn normalize_groups(groups: Vec<RawGroup>) -> EmojiDataset {
    let mut count = 0usize;
    let normalized: Vec<Value> = groups
        .into_iter()
        .map(|group| {
            count += group.emojis.len();
            json!({
                "name": group.name,
                "slug": group.slug,
                "emojis": group.emojis.into_iter().map(|e| json!({
                    "char": e.emoji,
                    "name": e.name,
                    "keywords": e.slug.replace('_', " "),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    EmojiDataset {
        count,
        groups: Value::Array(normalized),
    }
}

async fn fetch_emoji_dataset() -> Result<EmojiDataset, HttpResponse> {
    let url = crate::utils::security::urls::resolve_emoji_api_url();

    let resp = match crate::utils::http::outbound_http_client()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Error fetching emoji data from {}: {}", url, e);
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się połączyć z serwerem emotek." })));
        }
    };

    if !resp.status().is_success() {
        log::error!("Emoji API error {} for {}", resp.status(), url);
        return Err(HttpResponse::BadGateway()
            .json(json!({ "error": "Nie udało się pobrać listy emotek." })));
    }

    let raw_bytes = match crate::utils::http::read_response_limited(
        resp,
        crate::utils::http::MAX_EMOJI_DATASET_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Error reading emoji API response: {e:?}");
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się pobrać listy emotek." })));
        }
    };
    let raw = match String::from_utf8(raw_bytes) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Error reading emoji API response: {}", e);
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się pobrać listy emotek." })));
        }
    };

    let groups: Vec<RawGroup> = match serde_json::from_str(&raw) {
        Ok(g) => g,
        Err(e) => {
            log::error!("Invalid emoji API JSON from {}: {}", url, e);
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się pobrać listy emotek." })));
        }
    };

    if groups.is_empty() {
        return Err(HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Zbiór emotek jest niedostępny." })));
    }

    Ok(normalize_groups(groups))
}

async fn get_or_load_dataset() -> Result<EmojiDataset, HttpResponse> {
    {
        let cache = EMOJI_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref dataset) = *cache {
            return Ok(dataset.clone());
        }
    }

    let dataset = fetch_emoji_dataset().await?;
    *EMOJI_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(dataset.clone());
    Ok(dataset)
}

pub async fn get_emojis() -> HttpResponse {
    match get_or_load_dataset().await {
        Ok(dataset) if dataset.count == 0 => HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Zbiór emotek jest niedostępny." })),
        Ok(dataset) => HttpResponse::Ok()
            .insert_header(("Cache-Control", "public, max-age=604800, immutable"))
            .json(json!({ "count": dataset.count, "groups": dataset.groups })),
        Err(resp) => resp,
    }
}
