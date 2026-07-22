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
