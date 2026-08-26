// http.rs
// JSON błędów, timeouty wychodzące, parsowanie Turnstile.
// Zakres:
//  - wspólne HttpResponse
//  - JSON błędów, timeouty wychodzące, Turnstile parse
// Nie wyciekaj szczegółów Mongo w body.
// Przy zmianach: controllers, captcha.rs.

use std::time::Duration;

use futures_util::StreamExt;
use once_cell::sync::Lazy;
use reqwest::redirect::Policy;

static OUTBOUND: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(4))
        .redirect(Policy::limited(3))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub fn outbound_http_client() -> &'static reqwest::Client {
    &OUTBOUND
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitedBodyError {
    TooLarge,
    ReadFailed,
}

pub fn append_limited(
    buf: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), LimitedBodyError> {
    if buf.len().saturating_add(chunk.len()) > max_bytes {
        return Err(LimitedBodyError::TooLarge);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

pub async fn read_response_limited(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, LimitedBodyError> {
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(LimitedBodyError::TooLarge);
        }
    }

    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| LimitedBodyError::ReadFailed)?;
        append_limited(&mut buf, &chunk, max_bytes)?;
    }
    Ok(buf)
}

pub const MAX_GIPHY_JSON_BYTES: usize = 2 * 1024 * 1024;

pub const MAX_EMOJI_DATASET_BYTES: usize = 8 * 1024 * 1024;

pub const MAX_HIBP_RANGE_BYTES: usize = 512 * 1024;

pub const MAX_TURNSTILE_BYTES: usize = 64 * 1024;

pub const MAX_PROXY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
