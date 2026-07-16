use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use actix_web::HttpRequest;
use rand::Rng;

use crate::utils::app_env::is_production;

pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub fn build_csrf_cookie(token: &str) -> Cookie<'static> {
    Cookie::build(CSRF_COOKIE_NAME, token.to_string())
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::days(3))
        .finish()
}

/// Returns an existing CSRF token from the request cookie, or generates a new one.
pub fn csrf_token_for_response(req: &HttpRequest) -> (String, Option<Cookie<'static>>) {
    if let Some(cookie) = req.cookie(CSRF_COOKIE_NAME) {
        let value = cookie.value().trim();
        if !value.is_empty() {
            return (value.to_string(), None);
        }
    }

    let token = generate_csrf_token();
    (token.clone(), Some(build_csrf_cookie(&token)))
}

pub fn clear_csrf_cookie() -> Cookie<'static> {
    Cookie::build(CSRF_COOKIE_NAME, "")
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .finish()
}

/// Porównanie ciągów w czasie stałym, aby nie ujawniać dopasowania tokenu
/// przez czas odpowiedzi (ochrona przed atakami czasowymi).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
