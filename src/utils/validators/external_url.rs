fn extract_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split(':').next()?;
    Some(host.to_ascii_lowercase())
}

fn host_allowed(host: &str) -> bool {
    if host == "media.giphy.com"
        || host == "i.giphy.com"
        || host.ends_with(".giphy.com")
    {
        return true;
    }

    false
}

fn listening_host_allowed(host: &str) -> bool {
    host == "open.spotify.com"
        || host == "spotify.com"
        || host.ends_with(".spotify.com")
        || host == "i.scdn.co"
        || host == "mosaic.scdn.co"
        || host.ends_with(".scdn.co")
}

pub fn is_allowed_listening_url(url: &str) -> bool {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('\\') || trimmed.contains('@') {
        return false;
    }

    let Some(host) = extract_host(trimmed) else {
        return false;
    };

    listening_host_allowed(&host)
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
