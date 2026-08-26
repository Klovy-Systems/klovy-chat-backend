// url.rs
// Tylko poprawne https URL.
// Zakres:
//  - invite, embed
//  - https; http tylko świadomie w DEV
// http tylko świadomie (DEV).
// Przy zmianach: embeds.ts, invites.

fn host_allowed(host: &str) -> bool {
    if host == "media.giphy.com"
        || host == "i.giphy.com"
        || host.ends_with(".giphy.com")
    {
        return true;
    }

    false
}

pub fn is_allowed_external_media_url(url: &str) -> bool {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('\\') || trimmed.contains('@') {
        return false;
    }

    let parsed = match reqwest::Url::parse(trimmed) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    if host_allowed(host) {
        return true;
    }

    is_direct_https_image_url(&parsed)
}

fn is_direct_https_image_url(parsed: &reqwest::Url) -> bool {
    if parsed.scheme() != "https" {
        return false;
    }

    let path_and_query = format!(
        "{}{}",
        parsed.path(),
        parsed
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    );
    let path_lower = path_and_query.to_ascii_lowercase();

    if path_lower.ends_with(".gif")
        || path_lower.contains(".gif?")
        || path_lower.contains(".gif#")
        || path_lower.ends_with(".jpg")
        || path_lower.ends_with(".jpeg")
        || path_lower.ends_with(".png")
        || path_lower.ends_with(".webp")
        || path_lower.contains(".jpg?")
        || path_lower.contains(".jpeg?")
        || path_lower.contains(".png?")
        || path_lower.contains(".webp?")
    {
        return true;
    }

    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let trusted = matches!(
        host.as_str(),
        "cdn.discordapp.com"
            | "media.discordapp.net"
            | "i.imgur.com"
            | "media.tenor.com"
            | "images.unsplash.com"
            | "raw.githubusercontent.com"
    );

    trusted && parsed.path().split('/').any(|part| !part.is_empty())
}
