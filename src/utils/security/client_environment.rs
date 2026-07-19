//! Środowisko klienta raportowane przez oficjalną aplikację webową (z Client Hints / API przeglądarki).
pub const CLIENT_BROWSER_HEADER: &str = "x-klovy-client-browser";
pub const CLIENT_OS_HEADER: &str = "x-klovy-client-os";
pub const CLIENT_ENVIRONMENT_LABEL_HEADER: &str = "x-klovy-client-label";

/// Separator osadzony w `x-klovy-user-agent` — musi być widocznym ASCII (RFC 7230).
pub const CLIENT_ENV_TRANSPORT_MARKER: &str = "<<KLOVY_ENV>>";
pub const CLIENT_ENV_TRANSPORT_SEPARATOR: &str = "<<KLOVY_SEP>>";

#[derive(Debug, Clone, Default)]
pub struct ClientEnvironmentHints {
    pub browser: Option<String>,
    pub os: Option<String>,
    pub label: Option<String>,
}
