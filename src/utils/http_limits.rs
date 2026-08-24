use std::time::Duration;

use futures_util::StreamExt;
use once_cell::sync::Lazy;
use reqwest::redirect::Policy;

/// Shared client for outbound JSON APIs (Giphy, emoji dataset). Timeouts prevent
/// a hung upstream from occupying an Axum HTTP slot until `HTTP_EDGE_TIMEOUT`.
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

/// Read a response body with a hard cap. `Content-Length` is checked first, then
/// the stream is aborted as soon as the cap is exceeded (so a missing/lying
/// length cannot fill RAM).
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

/// Giphy search/trending JSON is small after our `limit<=50` cap.
pub const MAX_GIPHY_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Unicode emoji dataset JSON.
pub const MAX_EMOJI_DATASET_BYTES: usize = 8 * 1024 * 1024;
/// HIBP k-anonymity range list (padded).
pub const MAX_HIBP_RANGE_BYTES: usize = 512 * 1024;
/// Cloudflare Turnstile siteverify JSON.
pub const MAX_TURNSTILE_BYTES: usize = 64 * 1024;
/// Actix → Axum proxy response. Prevents a huge Mongo serialization from
/// occupying all 32 inflight slots with unbounded buffers.
pub const MAX_PROXY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
