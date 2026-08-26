// captcha.rs
// Turnstile siteverify; w DEV/braku klucza bypass.
// Zakres:
//  - outcome w extensions dla auth_fallback
//  - siteverify; DEV/brak klucza = bypass + outcome w extensions
// Token jednorazowy — nie cache'uj sukcesu między requestami.
// Przy zmianach: Captcha.tsx, auth_fallback.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::time::Duration;

use crate::utils::env::{is_development, is_production};

const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

static TURNSTILE_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(6))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnstileOutcome {
    Verified,
    Bypassed,
}

#[derive(Deserialize)]
struct TurnstileResponse {
    success: Option<bool>,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
}

fn is_signup_path(path: &str) -> bool {
    path.ends_with("/signup") || path.ends_with("/register")
}

#[derive(Deserialize)]
struct RequestBody {
    #[serde(rename = "turnstileToken")]
    turnstile_token: Option<String>,
}

pub async fn verify_turnstile_token(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let (http_req, payload) = req.into_parts();

    let body_bytes = crate::middlewares::read_body_bytes(payload).await?;

    if is_development() {
        let payload = actix_web::dev::Payload::from(body_bytes);
        let req = ServiceRequest::from_parts(http_req, payload);
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let parsed: Result<RequestBody, _> = serde_json::from_slice(&body_bytes);
    let token = parsed.ok().and_then(|b| b.turnstile_token);

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            let res = HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Turnstile token is required" }));
            return Ok(ServiceResponse::new(http_req, res));
        }
    };

    let secret = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();

    let verify_body = serde_json::json!({
        "secret": secret,
        "response": token,
    });

    let outcome = match TURNSTILE_CLIENT
        .post(SITEVERIFY_URL)
        .json(&verify_body)
        .send()
        .await
    {
        Ok(resp) => {
            match crate::utils::http::read_response_limited(
                resp,
                crate::utils::http::MAX_TURNSTILE_BYTES,
            )
            .await
            {
                Ok(bytes) => match serde_json::from_slice::<TurnstileResponse>(&bytes) {
                    Ok(data) if data.success == Some(true) => TurnstileOutcome::Verified,
                    Ok(data) => {
                        log::warn!(
                            "Turnstile verification failed: error-codes={:?}",
                            data.error_codes
                        );
                        let res = HttpResponse::BadRequest()
                            .json(serde_json::json!({ "error": "Invalid Turnstile token" }));
                        return Ok(ServiceResponse::new(http_req, res));
                    }
                    Err(e) => {
                        log::warn!("Turnstile response parse error: {e}");
                        if is_production() && is_signup_path(http_req.path()) {
                            let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                                "error": "Captcha verification is temporarily unavailable. Try again later.",
                                "code": "TURNSTILE_UNAVAILABLE"
                            }));
                            return Ok(ServiceResponse::new(http_req, res));
                        }
                        TurnstileOutcome::Bypassed
                    }
                },
                Err(e) => {
                    log::warn!("Turnstile response body error: {e:?}");
                    if is_production() && is_signup_path(http_req.path()) {
                        let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                            "error": "Captcha verification is temporarily unavailable. Try again later.",
                            "code": "TURNSTILE_UNAVAILABLE"
                        }));
                        return Ok(ServiceResponse::new(http_req, res));
                    }
                    TurnstileOutcome::Bypassed
                }
            }
        }
        Err(e) => {
            log::warn!("Turnstile siteverify request error: {e}");
            if is_production() && is_signup_path(http_req.path()) {
                let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                    "error": "Captcha verification is temporarily unavailable. Try again later.",
                    "code": "TURNSTILE_UNAVAILABLE"
                }));
                return Ok(ServiceResponse::new(http_req, res));
            }
            TurnstileOutcome::Bypassed
        }
    };

    http_req.extensions_mut().insert(outcome);

    let payload = actix_web::dev::Payload::from(body_bytes);
    let req = ServiceRequest::from_parts(http_req, payload);
    Ok(next.call(req).await?.map_into_boxed_body())
}
