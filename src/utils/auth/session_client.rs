#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub browser: String,
    pub os: String,
    pub label: String,
    pub is_known: bool,
}

fn windows_version(ua: &str) -> &'static str {
    if ua.contains("Windows NT 10.0") {
        "Windows 10"
    } else if ua.contains("Windows NT 11.0") {
        "Windows 11"
    } else if ua.contains("Windows NT 6.3") {
        "Windows 8.1"
    } else if ua.contains("Windows NT 6.2") {
        "Windows 8"
    } else if ua.contains("Windows NT 6.1") {
        "Windows 7"
    } else if ua.contains("Windows") {
        "Windows"
    } else {
        "Windows"
    }
}

fn android_device(ua: &str) -> Option<String> {
    let marker = "Android";
    let idx = ua.find(marker)?;
    let rest = &ua[idx..];
    let semi = rest.find(';')?;
    let after = rest[semi + 1..].trim();
    let model = after.split(';').next()?.trim();
    if model.is_empty()
        || model.eq_ignore_ascii_case("wv")
        || model.eq_ignore_ascii_case("mobile")
    {
        return None;
    }
    Some(model.to_string())
}

pub fn normalize_browser_name(browser: &str) -> String {
    match browser.trim().to_ascii_lowercase().as_str() {
        "opera gx" | "opera neon" => "Opera".to_string(),
        other if other.starts_with("opera ") => "Opera".to_string(),
        _ => browser.trim().to_string(),
    }
}

pub fn parse_user_agent(ua: &str) -> ClientInfo {
    let trimmed = ua.trim();
    if trimmed.is_empty() {
        return ClientInfo {
            browser: "Nieznana przeglądarka".to_string(),
            os: "Nieznany system".to_string(),
            label: "Nieznana sesja".to_string(),
            is_known: false,
        };
    }

    let ua_lower = trimmed.to_lowercase();

    let browser = if trimmed.contains("Stoat") {
        if ua_lower.contains("android") {
            "Stoat For Android"
        } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
            "Stoat IOS"
        } else {
            "Stoat For Web"
        }
    } else if trimmed.contains("Edg/") || trimmed.contains("EdgA/") || trimmed.contains("EdgiOS/") {
        "Edge"
    } else if trimmed.contains("OPR/") || ua_lower.contains("opera") {
        "Opera"
    } else if trimmed.contains("Firefox/") || ua_lower.contains("fxios") {
        "Firefox"
    } else if trimmed.contains("Brave/") || ua_lower.contains("brave") {
        "Brave"
    } else if trimmed.contains("CriOS/") {
        "Chrome"
    } else if trimmed.contains("Chrome/") {
        "Chrome"
    } else if trimmed.contains("Safari/") {
        "Safari"
    } else if ua_lower.contains("msie") || ua_lower.contains("trident/") {
        "Internet Explorer"
    } else {
        "Nieznana przeglądarka"
    };

    let browser = normalize_browser_name(browser);

    let os = if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        "IOS".to_string()
    } else if ua_lower.contains("android") {
        android_device(trimmed)
            .map(|model| format!("Android On {model}"))
            .unwrap_or_else(|| "Android".to_string())
    } else if ua_lower.contains("mac os x") || trimmed.contains("Macintosh") {
        "macOS".to_string()
    } else if ua_lower.contains("windows") {
        windows_version(trimmed).to_string()
    } else if ua_lower.contains("linux") {
        "Linux".to_string()
    } else {
        "Nieznany system".to_string()
    };

    let is_known = browser != "Nieznana przeglądarka";
    let label = format!("{browser} On {os}");

    ClientInfo {
        browser: browser.to_string(),
        os,
        label,
        is_known,
    }
}
