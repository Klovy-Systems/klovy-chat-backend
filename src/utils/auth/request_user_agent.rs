use actix_web::HttpRequest;

use crate::utils::security::client_user_agent::CLIENT_USER_AGENT_HEADER;

pub fn user_agent_from_request(req: &HttpRequest) -> String {
    let raw = req
        .headers()
        .get(CLIENT_USER_AGENT_HEADER)
        .or_else(|| req.headers().get("user-agent"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    raw.split(crate::utils::security::client_environment::CLIENT_ENV_TRANSPORT_MARKER)
        .next()
        .unwrap_or(raw)
        .trim()
        .to_string()
}
