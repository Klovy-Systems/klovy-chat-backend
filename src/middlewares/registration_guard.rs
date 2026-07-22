use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::registration::is_registration_disabled;

pub async fn registration_guard(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if is_registration_disabled() {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden().json(serde_json::json!({
            "message": "Rejestracja nowych kont jest obecnie wyłączona.",
            "code": "REGISTRATION_DISABLED"
        }));
        return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
