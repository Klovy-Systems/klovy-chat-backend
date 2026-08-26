// validation.rs
// Wstępne limity/walidacja zanim kontroler.
// Zakres:
//  - uzupełnia json/sanitize middleware
//  - wstępne limity; ciężka logika zostaje w kontrolerze
// Nie duplikuj ciężkiej logiki biznesowej tutaj.
// Przy zmianach: validators/json.rs, sanitize.rs.

use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

pub async fn validate_password(
    req: ServiceRequest,
    next: Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let (http_req, payload) = req.into_parts();

    let body_bytes = crate::middlewares::read_body_bytes(payload).await?;

    #[derive(serde::Deserialize)]
    struct PasswordBody {
        password: Option<String>,
        #[serde(rename = "newPassword")]
        new_password: Option<String>,
    }

    let body: PasswordBody = serde_json::from_slice(&body_bytes).unwrap_or(PasswordBody {
        password: None,
        new_password: None,
    });

    let password_to_validate = body.password.or(body.new_password);

    let password = match password_to_validate {
        Some(p) if !p.is_empty() => p,
        _ => {
            let res = HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Password is required" }));
            return Ok(ServiceResponse::new(http_req, res));
        }
    };

    let has_min_length = password.len() >= 8;
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| matches!(c, '@' | '$' | '!' | '%' | '*' | '?' | '&'));

    if !(has_min_length && has_lower && has_upper && has_digit && has_special) {
        let res = HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters long and contain uppercase, lowercase, number and special character"
        }));
        return Ok(ServiceResponse::new(http_req, res));
    }

    let payload = actix_web::dev::Payload::from(body_bytes.clone());
    let req = ServiceRequest::from_parts(http_req, payload);
    Ok(next.call(req).await?.map_into_boxed_body())
}
