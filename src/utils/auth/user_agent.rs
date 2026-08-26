// user_agent.rs
// Parsowanie UA do etykiety sesji.
// Zakres:
//  - OS/browser
//  - UA → etykieta sesji (OS/browser)
// Duplikat tematu z security/user_agent — HTTP vs surowy nagłówek.
// Przy zmianach: session.rs, OsIcon.

use actix_web::HttpRequest;

use crate::utils::security::user_agent::CLIENT_USER_AGENT_HEADER;

pub fn user_agent_from_request(req: &HttpRequest) -> String {
    let raw = req
        .headers()
        .get(CLIENT_USER_AGENT_HEADER)
        .or_else(|| req.headers().get("user-agent"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    raw.split(crate::utils::security::client::CLIENT_ENV_TRANSPORT_MARKER)
        .next()
        .unwrap_or(raw)
        .trim()
        .to_string()
}
