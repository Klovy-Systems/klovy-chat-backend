use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::{header, Method},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::upload_limits::MAX_JSON_PAYLOAD_BYTES;

pub async fn validate_json_payload_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let method = req.method().clone();

    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false);

        if is_json {
            let content_length = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            if content_length > MAX_JSON_PAYLOAD_BYTES {
                let (req, _) = req.into_parts();
                let res = HttpResponse::PayloadTooLarge()
                    .json(serde_json::json!({ "error": "Payload too large" }));
                return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
            }
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
