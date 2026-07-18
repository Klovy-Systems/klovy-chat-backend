use actix_web::HttpRequest;

use crate::utils::security::client_environment::{
    ClientEnvironmentHints, CLIENT_BROWSER_HEADER, CLIENT_ENVIRONMENT_LABEL_HEADER,
    CLIENT_OS_HEADER,
};

fn read_header(req: &HttpRequest, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn client_environment_from_request(req: &HttpRequest) -> ClientEnvironmentHints {
    ClientEnvironmentHints {
        browser: read_header(req, CLIENT_BROWSER_HEADER),
        os: read_header(req, CLIENT_OS_HEADER),
        label: read_header(req, CLIENT_ENVIRONMENT_LABEL_HEADER),
    }
}
