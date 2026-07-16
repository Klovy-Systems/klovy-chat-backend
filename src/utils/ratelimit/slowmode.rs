use std::time::Duration;

use super::Store;

static SLOWMODE: once_cell::sync::Lazy<Store> =
    once_cell::sync::Lazy::new(|| Store::new(1, Duration::from_secs(1)));

fn slowmode_key(user_id: &str, channel_id: &str) -> String {
    format!("slowmode:{user_id}:{channel_id}")
}

/// Returns `Ok(())` when the user may send, or `Err(retry_after_secs)` when slowmode applies.
pub async fn check_channel_slowmode(
    user_id: &str,
    channel_id: &str,
    rate_limit_secs: u32,
    bypass: bool,
) -> Result<(), u64> {
    if bypass || rate_limit_secs == 0 {
        return Ok(());
    }

    let window = Duration::from_secs(rate_limit_secs as u64);
    let key = slowmode_key(user_id, channel_id);

    if SLOWMODE.check_and_increment_with_window(&key, 1, window) {
        Ok(())
    } else {
        Err(rate_limit_secs as u64)
    }
}
