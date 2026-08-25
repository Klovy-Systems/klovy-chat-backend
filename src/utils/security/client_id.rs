//! Identyfikacja oficjalnego klienta aplikacji (KlovyChatApp).
//!
//! Oficjalny frontend dołącza nagłówek `X-Klovy-Client: KlovyChatApp/<wersja>`
//! do każdego żądania HTTP oraz parametr `?client=KlovyChatApp` przy handshake
//! WebSocket. Ruch, który nie przedstawia tego identyfikatora, jest traktowany
//! jako podejrzany (boty/skanery/wolumetryczne floody) i tanio odrzucany zanim
//! trafi do logiki uwierzytelniania czy bazy danych.
//!
//! UWAGA: to jest warstwa filtrująca (defense-in-depth), a nie mechanizm
//! uwierzytelniania — stały identyfikator da się skopiować. Realne bezpieczeństwo
//! zapewniają JWT/CSRF/rate limiting; ten filtr obniża jedynie szum od
//! niespersonalizowanego ruchu ataków DoS/DDoS.

/// Nazwa nagłówka HTTP przenoszącego identyfikator klienta (lowercase — Actix).
pub const CLIENT_HEADER_NAME: &str = "x-klovy-client";

/// Nazwa parametru zapytania używana przy handshake WebSocket.
pub const CLIENT_QUERY_PARAM: &str = "client";

/// Oczekiwany identyfikator oficjalnego klienta (bez sufiksu wersji).
pub const EXPECTED_CLIENT: &str = "KlovyChatApp";

/// Sprawdza, czy podana wartość pochodzi od oficjalnego klienta.
/// Akceptuje zarówno `KlovyChatApp`, jak i `KlovyChatApp/1.2.3`.
pub fn is_valid_client_identifier(value: &str) -> bool {
    let v = value.trim();
    v == EXPECTED_CLIENT
        || v
            .strip_prefix(EXPECTED_CLIENT)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Weryfikuje parametr `?client=` w surowym query stringu (np. handshake WS, OAuth redirect).
pub fn query_client_valid(raw_query: Option<&str>) -> bool {
    let Some(query) = raw_query else {
        return false;
    };
    query.split('&').any(|pair| {
        let mut it = pair.splitn(2, '=');
        matches!(
            (it.next(), it.next()),
            (Some(key), Some(value))
                if key == CLIENT_QUERY_PARAM && is_valid_client_identifier(value)
        )
    })
}

/// Nazwa parametru jednorazowego tokenu klucza szyfrującego ramki WebSocket.
pub const WS_CRYPTO_QUERY_PARAM: &str = "wsk";

pub fn query_param(raw_query: Option<&str>, name: &str) -> Option<String> {
    let query = raw_query?;
    query.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(key), Some(value)) if key == name => Some(value.to_string()),
            _ => None,
        }
    })
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_loose(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn canonicalize_request_path(path: &str) -> String {
    let decoded = percent_decode_loose(path);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return "/".to_string();
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/").to_ascii_lowercase());
    out
}

pub(crate) fn is_security_webhook_path(path: &str) -> bool {
    path == "/api/security" || path.starts_with("/api/security/")
}

fn is_public_info_path(path: &str) -> bool {
    path == "/" || path == "/api"
}

/// True when this HTTP path must present `X-Klovy-Client` (or `?client=` on GET).
pub fn requires_client_identifier(path: &str) -> bool {
    let path = canonicalize_request_path(path);
    !is_public_info_path(&path) && !is_security_webhook_path(&path)
}

/// Cheap official-client check for Axum (before body) and Actix (defense in depth).
pub fn official_client_presented(
    method: &str,
    path: &str,
    query: Option<&str>,
    header_value: Option<&str>,
) -> bool {
    if method.eq_ignore_ascii_case("OPTIONS") {
        return true;
    }
    let path = canonicalize_request_path(path);
    let method_upper = method.to_ascii_uppercase();
    if matches!(method_upper.as_str(), "GET" | "HEAD")
        && (is_public_info_path(&path) || is_security_webhook_path(&path))
    {
        return true;
    }
    if header_value.is_some_and(is_valid_client_identifier) {
        return true;
    }
    method_upper == "GET" && query_client_valid(query)
}
