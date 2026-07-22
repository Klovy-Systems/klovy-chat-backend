use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
};
use actix_web_lab::middleware::Next;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;

use super::unicode_text::{
    sanitize_unicode_text, MAX_MESSAGE_BYTES, MAX_MESSAGE_CHARS, MAX_MESSAGE_COMBINING,
};

lazy_static! {
    static ref SCRIPT_TAG: Regex =
        Regex::new(r"(?is)<script\b[^>]*>.*?</script>").unwrap();
    static ref JS_PROTO: Regex = Regex::new(r"(?i)javascript:").unwrap();
    static ref ON_EVENT: Regex = Regex::new(r"(?i)on\w+\s*=").unwrap();
}

pub fn sanitize_message_content(input: &str) -> String {
    let cleaned = strip_dangerous(input.trim());
    sanitize_unicode_text(
        &cleaned,
        MAX_MESSAGE_CHARS,
        MAX_MESSAGE_BYTES,
        MAX_MESSAGE_COMBINING,
    )
}

pub fn strip_dangerous(input: &str) -> String {
    let s = SCRIPT_TAG.replace_all(input, "");
    let s = JS_PROTO.replace_all(&s, "");
    let s = ON_EVENT.replace_all(&s, "");
    s.into_owned()
}

fn sanitize_json_value(value: &mut Value) {
    match value {
        Value::String(s) => {
            let cleaned = sanitize_message_content(s.trim());
            *s = cleaned;
        }
        Value::Array(items) => {
            for item in items {
                sanitize_json_value(item);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                sanitize_json_value(v);
            }
        }
        _ => {}
    }
}

pub async fn sanitize_input_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let method = req.method().clone();
    if !matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let content_type = req
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/json") {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let (http_req, payload) = req.into_parts();
    let body_bytes = crate::middlewares::read_body_bytes(payload).await?;

    if body_bytes.is_empty() {
        let payload = actix_web::dev::Payload::from(body_bytes);
        let req = ServiceRequest::from_parts(http_req, payload);
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let mut body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            let payload = actix_web::dev::Payload::from(body_bytes);
            let (http_req, _) = ServiceRequest::from_parts(http_req, payload).into_parts();
            let res = actix_web::HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Invalid JSON body" }));
            return Ok(actix_web::dev::ServiceResponse::new(http_req, res).map_into_boxed_body());
        }
    };

    sanitize_json_value(&mut body);
    let new_body_bytes = serde_json::to_vec(&body).unwrap_or(body_bytes.to_vec());
    let payload = actix_web::dev::Payload::from(actix_web::web::Bytes::from(new_body_bytes));
    let req = ServiceRequest::from_parts(http_req, payload);

    Ok(next.call(req).await?.map_into_boxed_body())
}
