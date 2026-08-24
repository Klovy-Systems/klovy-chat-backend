use http::HeaderMap;

use crate::utils::app_env::is_production;

fn proto_token_is_https(token: &str) -> bool {
    token.trim().eq_ignore_ascii_case("https")
}

/// Leftmost `X-Forwarded-Proto` value (client-facing hop).
fn x_forwarded_proto_https(raw: &str) -> bool {
    raw.split(',')
        .next()
        .map(proto_token_is_https)
        .unwrap_or(false)
}

/// RFC 7239 `Forwarded` — first `proto=` parameter in the chain.
fn forwarded_proto_https(raw: &str) -> bool {
    for element in raw.split(',') {
        for part in element.split(';') {
            let part = part.trim();
            if let Some(value) = part
                .strip_prefix("proto=")
                .or_else(|| part.strip_prefix("Proto="))
            {
                let value = value.trim().trim_matches('"');
                return proto_token_is_https(value);
            }
        }
    }
    false
}

/// Cloudflare `Cf-Visitor: {"scheme":"https"}` — useful when Caddy overwrites
/// `X-Forwarded-Proto` based on the cleartext tunnel hop (cloudflared → Caddy).
fn cf_visitor_https(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("\"scheme\":\"https\"") || lower.contains("\"scheme\": \"https\"")
}

/// Inspect proxy headers for an HTTPS client-facing hop (ignores `NODE_ENV`).
pub fn proxy_headers_indicate_https(headers: &HeaderMap) -> bool {
    if let Some(raw) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        if x_forwarded_proto_https(raw) {
            return true;
        }
    }

    if let Some(raw) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        if forwarded_proto_https(raw) {
            return true;
        }
    }

    if let Some(raw) = headers.get("cf-visitor").and_then(|v| v.to_str().ok()) {
        if cf_visitor_https(raw) {
            return true;
        }
    }

    false
}

/// True when the client connection reached us over HTTPS (via reverse proxy).
pub fn is_secure_client_connection(headers: &HeaderMap) -> bool {
    if !is_production() {
        return true;
    }
    proxy_headers_indicate_https(headers)
}
