// signup.rs
// Odrzuca rejestrację gdy registration disabled.
// Zakres:
//  - osobna nazwa funkcji, żeby nie kolidować z handlerem signup
//  - 403 gdy registration disabled; flaga z registration/mod.rs
// Flaga z registration/mod.rs.
// Przy zmianach: utils/registration/mod.rs, controllers/auth.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::registration::is_registration_disabled;

pub async fn registration_closed(
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
