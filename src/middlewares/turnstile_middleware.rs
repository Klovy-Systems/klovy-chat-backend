use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::time::Duration;

use crate::utils::app_env::is_development;

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
    let client_ip = crate::utils::client_ip::client_ip_from_http_request(&http_req);
    let mut verify_body = serde_json::json!({
        "secret": secret,
        "response": token,
    });
    if client_ip != "unknown" {
        verify_body["remoteip"] = serde_json::Value::String(client_ip);
    }

    let outcome = match TURNSTILE_CLIENT
        .post(SITEVERIFY_URL)
        .json(&verify_body)
        .send()
        .await
    {
        Ok(resp) => match resp.json::<TurnstileResponse>().await {
            Ok(data) if data.success == Some(true) => TurnstileOutcome::Verified,
            Ok(_) => {
                let res = HttpResponse::BadRequest()
                    .json(serde_json::json!({ "error": "Invalid Turnstile token" }));
                return Ok(ServiceResponse::new(http_req, res));
            }
            Err(_) => TurnstileOutcome::Bypassed,
        },
        Err(_) => TurnstileOutcome::Bypassed,
    };

    http_req.extensions_mut().insert(outcome);

    let payload = actix_web::dev::Payload::from(body_bytes);
    let req = ServiceRequest::from_parts(http_req, payload);
    Ok(next.call(req).await?.map_into_boxed_body())
}
