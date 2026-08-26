// env.rs
// Flaga produkcji.
// Zakres:
//  - cookie secure, Turnstile, CORS
//  - is_production: cookie secure, Turnstile, CORS
// Nie mylić z FE import.meta.env.
// Przy zmianach: main.rs, cors.rs.

use std::env;

pub fn node_env() -> String {
    env::var("NODE_ENV")
        .unwrap_or_else(|_| "development".to_string())
        .to_ascii_lowercase()
}

pub fn is_production() -> bool {
    node_env() == "production"
}

pub fn is_development() -> bool {
    !is_production()
}
