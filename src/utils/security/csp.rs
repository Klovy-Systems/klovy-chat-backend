// csp.rs
// Nagłówki CSP.
// Zakres:
//  - XSS
//  - XSS headers; nowy iframe = tu + FE embeds
// Nowy embed iframe: tu + FE embeds.
// Przy zmianach: server.rs security headers.

use std::env;

fn cdn_image_host() -> String {
    env::var("CDN_PUBLIC_BASE_URL")
        .ok()
        .map(|raw| {
            let trimmed = raw.trim().trim_end_matches('/');
            let without_scheme = trimmed
                .strip_prefix("https://")
                .or_else(|| trimmed.strip_prefix("http://"))
                .unwrap_or(trimmed);
            without_scheme
                .split('/')
                .next()
                .unwrap_or("cdn.klovy.chat")
                .to_string()
        })
        .unwrap_or_else(|| "cdn.klovy.chat".to_string())
}

pub fn content_security_policy(include_upgrade_insecure: bool) -> String {
    let cdn_host = cdn_image_host();
    let mut policy = format!(
        "default-src 'self'; \
        script-src 'self' https://challenges.cloudflare.com; \
        frame-src https://challenges.cloudflare.com; \
        connect-src 'self' https: wss:; \
        img-src 'self' data: blob: https://{cdn_host} https://*.giphy.com; \
        media-src 'self' data: blob: https://{cdn_host}; \
        worker-src 'self' blob:; \
        style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
        font-src 'self' https://fonts.gstatic.com; \
        object-src 'none'; \
        base-uri 'self'; \
        form-action 'self'; \
        frame-ancestors 'none'"
    );

    if include_upgrade_insecure {
        policy.push_str("; upgrade-insecure-requests");
    }

    policy
}
