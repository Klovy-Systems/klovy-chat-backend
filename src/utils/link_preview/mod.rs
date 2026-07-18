use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::redirect::Policy;
use serde::Serialize;

static PREVIEW_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(Policy::limited(3))
        .timeout(Duration::from_secs(6))
        .user_agent("KlovyChatLinkPreview/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

const MAX_HTML_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkPreview {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn host_is_blocked(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }
    if host == "metadata.google.internal" {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_private_ip(ip);
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return is_private_ip(IpAddr::V4(v4));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return is_private_ip(IpAddr::V6(v6));
    }
    false
}

pub fn is_safe_preview_target(url: &str) -> bool {
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

    if parsed.username() != "" || parsed.password().is_some() {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    !host_is_blocked(host)
}

fn meta_content(html: &str, property: &str) -> Option<String> {
    let escaped = regex::escape(property);
    let patterns = [
        format!(r#"(?is)<meta[^>]+property=["']{escaped}["'][^>]+content=["']([^"']+)["']"#),
        format!(r#"(?is)<meta[^>]+content=["']([^"']+)["'][^>]+property=["']{escaped}["']"#),
        format!(r#"(?is)<meta[^>]+name=["']{escaped}["'][^>]+content=["']([^"']+)["']"#),
        format!(r#"(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']{escaped}["']"#),
    ];

    for pattern in patterns {
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };
        if let Some(caps) = re.captures(html) {
            let value = caps.get(1)?.as_str().trim();
            if !value.is_empty() {
                return Some(decode_basic_entities(value));
            }
        }
    }

    None
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn normalize_preview_image(base: &reqwest::Url, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let resolved = if trimmed.starts_with("//") {
        reqwest::Url::parse(&format!("https:{trimmed}")).ok()
    } else if trimmed.starts_with("https://") {
        reqwest::Url::parse(trimmed).ok()
    } else if trimmed.starts_with('/') {
        base.join(trimmed).ok()
    } else {
        base.join(trimmed).ok()
    }?;

    if resolved.scheme() != "https" {
        return None;
    }

    let host = resolved.host_str()?;
    if host_is_blocked(host) {
        return None;
    }

    Some(resolved.to_string())
}

fn extract_title(html: &str) -> Option<String> {
    meta_content(html, "og:title")
        .or_else(|| meta_content(html, "twitter:title"))
        .or_else(|| {
            let re = Regex::new(r"(?is)<title[^>]*>([^<]+)</title>").ok()?;
            let caps = re.captures(html)?;
            let value = caps.get(1)?.as_str().trim();
            if value.is_empty() {
                None
            } else {
                Some(decode_basic_entities(value))
            }
        })
}

pub async fn fetch_link_preview(url: &str) -> Result<LinkPreview, &'static str> {
    if !is_safe_preview_target(url) {
        return Err("Invalid preview URL.");
    }

    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| "Invalid preview URL.")?;
    let response = PREVIEW_CLIENT
        .get(parsed.clone())
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .send()
        .await
        .map_err(|_| "Failed to fetch preview.")?;

    if !response.status().is_success() {
        return Err("Preview unavailable.");
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if !content_type.contains("text/html") && !content_type.contains("application/xhtml") {
        return Err("Preview unavailable.");
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|_| "Failed to read preview.")?;
    if bytes.len() > MAX_HTML_BYTES {
        return Err("Preview too large.");
    }

    let html = String::from_utf8_lossy(&bytes);
    let title = extract_title(&html);
    let description = meta_content(&html, "og:description")
        .or_else(|| meta_content(&html, "twitter:description"))
        .or_else(|| meta_content(&html, "description"));
    let site_name = meta_content(&html, "og:site_name");
    let image = meta_content(&html, "og:image")
        .or_else(|| meta_content(&html, "twitter:image"))
        .or_else(|| meta_content(&html, "twitter:image:src"))
        .and_then(|raw| normalize_preview_image(&parsed, &raw));

    if title.is_none() && description.is_none() && image.is_none() {
        return Err("Preview unavailable.");
    }

    Ok(LinkPreview {
        url: parsed.to_string(),
        title,
        description,
        image,
        site_name,
    })
}
