use std::env;

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

pub fn is_whitelist_enabled() -> bool {
    env_flag("WHITELIST_ENABLED")
}
