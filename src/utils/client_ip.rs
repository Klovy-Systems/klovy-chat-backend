use std::net::SocketAddr;

use actix_web::{dev::ServiceRequest, HttpRequest};
use http::HeaderMap;

fn trust_proxy_headers() -> bool {
    std::env::var("TRUST_PROXY")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn ip_from_http_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = value.trim();
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }

    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }

    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in forwarded.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("for=") {
                let value = value.trim().trim_matches('"');
                if value.starts_with('[') {
                    if let Some(end) = value.find(']') {
                        return Some(value[1..end].to_string());
                    }
                } else if let Some(host) = value.split(':').next() {
                    if !host.is_empty() {
                        return Some(host.to_string());
                    }
                }
            }
        }
    }

    None
}

fn ip_from_actix_headers(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = value.trim();
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }

    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }

    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in forwarded.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("for=") {
                let value = value.trim().trim_matches('"');
                if value.starts_with('[') {
                    if let Some(end) = value.find(']') {
                        return Some(value[1..end].to_string());
                    }
                } else if let Some(host) = value.split(':').next() {
                    if !host.is_empty() {
                        return Some(host.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Resolve the client IP from proxy headers or the direct connection.
pub fn client_ip_from_headers(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_http_headers(headers) {
            return ip;
        }
    }

    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn client_ip_from_http_request(req: &HttpRequest) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_actix_headers(req.headers()) {
            return ip;
        }
    }

    req.connection_info()
        .realip_remote_addr()
        .map(str::to_string)
        .or_else(|| req.connection_info().peer_addr().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn client_ip_from_service_request(req: &ServiceRequest) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_actix_headers(req.headers()) {
            return ip;
        }
    }

    req.connection_info()
        .peer_addr()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
