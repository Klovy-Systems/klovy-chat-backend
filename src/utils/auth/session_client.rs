use crate::utils::security::client_environment::ClientEnvironmentHints;

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub browser: String,
    pub os: String,
    pub label: String,
    pub is_known: bool,
}

const MAX_LABEL_LEN: usize = 160;

fn sanitize_client_label(value: Option<&String>) -> Option<String> {
    let raw = value?.trim();
    if raw.is_empty() || raw.len() > MAX_LABEL_LEN {
        return None;
    }
    if raw.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(raw.to_string())
}

fn short_version(version: &str, parts: usize) -> String {
    let chunks: Vec<&str> = version.split('.').filter(|part| !part.is_empty()).collect();
    if chunks.len() <= parts {
        return version.to_string();
    }
    chunks[..parts].join(".")
}

fn extract_platform_from_user_agent(ua: &str) -> Option<String> {
    let start = ua.find('(')?;
    let rest = &ua[start + 1..];
    let end = rest.find(')')?;
    let inner = rest[..end].trim();
    if inner.is_empty() {
        return None;
    }

    let noise = [
        "X11", "WOW64", "Win64", "U", "Mobile", "Tablet", "compatible",
    ];

    let segments: Vec<String> = inner
        .split(';')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .filter(|part| {
            !noise.iter().any(|n| part.eq_ignore_ascii_case(n))
                && !part.starts_with("rv:")
        })
        .map(str::to_string)
        .collect();

    if segments.is_empty() {
        return None;
    }
    Some(segments.join(" · "))
}

fn extract_browser_from_user_agent(ua: &str) -> Option<String> {
    let rules: &[(&str, &str)] = &[
        ("Edg/", "Edge"),
        ("EdgA/", "Edge"),
        ("EdgiOS/", "Edge"),
        ("OPR/", "Opera"),
        ("Vivaldi/", "Vivaldi"),
        ("Firefox/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
    ];

    for (needle, name) in rules {
        if let Some(idx) = ua.find(needle) {
            let version_start = idx + needle.len();
            let version: String = ua[version_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                return Some(format!("{name} {}", short_version(&version, 2)));
            }
            return Some(name.to_string());
        }
    }

    if let Some(idx) = ua.find("Version/") {
        let version_start = idx + "Version/".len();
        let version: String = ua[version_start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if ua.contains("Safari") {
            if version.is_empty() {
                return Some("Safari".to_string());
            }
            return Some(format!("Safari {}", short_version(&version, 2)));
        }
    }

    None
}

fn fallback_from_user_agent(ua: &str) -> ClientInfo {
    let trimmed = ua.trim();
    if trimmed.is_empty() {
        return ClientInfo {
            browser: "Unknown browser".to_string(),
            os: "Unknown OS".to_string(),
            label: "Unknown session".to_string(),
            is_known: false,
        };
    }

    let browser = extract_browser_from_user_agent(trimmed)
        .unwrap_or_else(|| "Unknown browser".to_string());
    let os = extract_platform_from_user_agent(trimmed)
        .unwrap_or_else(|| "Unknown OS".to_string());
    let is_known = browser != "Unknown browser";
    let label = format!("{browser} on {os}");

    ClientInfo {
        browser,
        os,
        label,
        is_known,
    }
}

pub fn normalize_browser_name(browser: &str) -> String {
    match browser.trim().to_ascii_lowercase().as_str() {
        "opera gx" | "opera neon" => "Opera".to_string(),
        other if other.starts_with("opera ") => "Opera".to_string(),
        _ => browser.trim().to_string(),
    }
}

pub fn resolve_client_info(ua: &str, env: &ClientEnvironmentHints) -> ClientInfo {
    if let (Some(browser), Some(os)) = (
        sanitize_client_label(env.browser.as_ref()),
        sanitize_client_label(env.os.as_ref()),
    ) {
        let browser = normalize_browser_name(&browser);
        let label = sanitize_client_label(env.label.as_ref())
            .unwrap_or_else(|| format!("{browser} on {os}"));
        return ClientInfo {
            browser,
            os,
            label,
            is_known: true,
        };
    }

    fallback_from_user_agent(ua)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::security::client_environment::ClientEnvironmentHints;

    fn env(browser: Option<&str>, os: Option<&str>) -> ClientEnvironmentHints {
        ClientEnvironmentHints {
            browser: browser.map(str::to_string),
            os: os.map(str::to_string),
            label: None,
        }
    }

    #[test]
    fn prefers_client_reported_environment() {
        let ua = "Mozilla/5.0";
        let info = resolve_client_info(
            ua,
            &env(
                Some("Google Chrome 120.0"),
                Some("Windows 15.0 · x86 · 64-bit"),
            ),
        );
        assert_eq!(info.browser, "Google Chrome 120.0");
        assert_eq!(info.os, "Windows 15.0 · x86 · 64-bit");
        assert_eq!(info.label, "Google Chrome 120.0 on Windows 15.0 · x86 · 64-bit");
    }

    #[test]
    fn fallback_extracts_user_agent_parenthetical() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        let info = resolve_client_info(ua, &ClientEnvironmentHints::default());
        assert_eq!(info.os, "Windows NT 10.0 · x64");
        assert_eq!(info.browser, "Chrome 120.0");
    }

    #[test]
    fn fallback_extracts_linux_segments() {
        let ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Firefox/121.0";
        let info = resolve_client_info(ua, &ClientEnvironmentHints::default());
        assert_eq!(info.os, "Ubuntu · Linux x86_64");
        assert_eq!(info.browser, "Firefox 121.0");
    }
}
