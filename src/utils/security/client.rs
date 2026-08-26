// client.rs
// Raportowane środowisko z oficjalnej apki.
// Zakres:
//  - hints
//  - hints środowiska z oficjalnej apki
// Spójne z auth/client.rs.
// Przy zmianach: clientInfo.ts.

pub const CLIENT_BROWSER_HEADER: &str = "x-klovy-client-browser";
pub const CLIENT_OS_HEADER: &str = "x-klovy-client-os";
pub const CLIENT_ENVIRONMENT_LABEL_HEADER: &str = "x-klovy-client-label";

pub const CLIENT_ENV_TRANSPORT_MARKER: &str = "<<KLOVY_ENV>>";
pub const CLIENT_ENV_TRANSPORT_SEPARATOR: &str = "<<KLOVY_SEP>>";

#[derive(Debug, Clone, Default)]
pub struct ClientEnvironmentHints {
    pub browser: Option<String>,
    pub os: Option<String>,
    pub label: Option<String>,
}
