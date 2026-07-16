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
    if trimmed.contains("..") || trimmed.contains('\\') {
        return false;
    }

    let Some(host) = extract_host(trimmed) else {
        return false;
    };

    host_allowed(&host)
}
