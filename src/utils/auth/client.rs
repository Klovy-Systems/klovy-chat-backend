// client.rs
// Odczyt środowiska z X-Klovy-User-Agent / hints.
// Zakres:
//  - sesje
//  - parser X-Klovy-User-Agent jak FE clientInfo.ts
// Parser musi umieć to co FE clientInfo.ts koduje.
// Przy zmianach: clientInfo.ts, metadata.rs.

use actix_web::HttpRequest;

use crate::utils::security::client::{
    ClientEnvironmentHints, CLIENT_BROWSER_HEADER, CLIENT_ENVIRONMENT_LABEL_HEADER,
    CLIENT_ENV_TRANSPORT_MARKER, CLIENT_ENV_TRANSPORT_SEPARATOR, CLIENT_OS_HEADER,
};
use crate::utils::security::user_agent::CLIENT_USER_AGENT_HEADER;

fn read_header(req: &HttpRequest, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn environment_from_user_agent_header(raw: &str) -> Option<ClientEnvironmentHints> {
    let env_payload = raw.split(CLIENT_ENV_TRANSPORT_MARKER).nth(1)?;
    let mut parts = env_payload.split(CLIENT_ENV_TRANSPORT_SEPARATOR);
    let browser = parts.next()?.trim();
    let os = parts.next()?.trim();
    if browser.is_empty() || os.is_empty() {
        return None;
    }

    Some(ClientEnvironmentHints {
        browser: Some(browser.to_string()),
        os: Some(os.to_string()),
        label: None,
    })
}

pub fn client_environment_from_request(req: &HttpRequest) -> ClientEnvironmentHints {
    if let (Some(browser), Some(os)) = (
        read_header(req, CLIENT_BROWSER_HEADER),
        read_header(req, CLIENT_OS_HEADER),
    ) {
        return ClientEnvironmentHints {
            browser: Some(browser),
            os: Some(os),
            label: read_header(req, CLIENT_ENVIRONMENT_LABEL_HEADER),
        };
    }

    if let Some(raw) = read_header(req, CLIENT_USER_AGENT_HEADER) {
        if let Some(env) = environment_from_user_agent_header(&raw) {
            return env;
        }
    }

    ClientEnvironmentHints::default()
}
