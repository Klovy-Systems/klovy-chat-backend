// bots.rs
// Honeypot i sygnały automatyzacji.
// Zakres:
//  - auth_fallback
//  - honeypot i automatyzacja; nie karz wolnego TOTP
// Nie karz prawdziwych userów za wolny TOTP.
// Przy zmianach: auth_fallback.rs.

pub fn is_known_bot_user_agent(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_ascii_lowercase();
    const KNOWN_BOTS: &[&str] = &[
        "googlebot",
        "bingbot",
        "yandexbot",
        "duckduckbot",
        "baiduspider",
        "slurp",
        "facebookexternalhit",
        "twitterbot",
        "discordbot",
        "curl/",
        "wget/",
        "python-requests",
        "go-http-client",
        "scrapy",
        "masscan",
        "nikto",
        "sqlmap",
        "dirbuster",
        "gobuster",
    ];

    KNOWN_BOTS.iter().any(|bot| ua_lower.contains(bot))
}
