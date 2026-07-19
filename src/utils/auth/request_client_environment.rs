use actix_web::HttpRequest;

use crate::utils::security::client_environment::{
    ClientEnvironmentHints, CLIENT_BROWSER_HEADER, CLIENT_ENVIRONMENT_LABEL_HEADER,
    CLIENT_ENV_TRANSPORT_MARKER, CLIENT_ENV_TRANSPORT_SEPARATOR, CLIENT_OS_HEADER,
};
use crate::utils::security::client_user_agent::CLIENT_USER_AGENT_HEADER;

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn parses_environment_embedded_in_user_agent_header() {
        let req = TestRequest::default()
            .insert_header((
                CLIENT_USER_AGENT_HEADER,
                format!(
                    "Mozilla/5.0 Chrome/120{CLIENT_ENV_TRANSPORT_MARKER}Google Chrome 120{CLIENT_ENV_TRANSPORT_SEPARATOR}Windows 11"
                ),
            ))
            .to_http_request();

        let env = client_environment_from_request(&req);
        assert_eq!(env.browser.as_deref(), Some("Google Chrome 120"));
        assert_eq!(env.os.as_deref(), Some("Windows 11"));
    }
}
