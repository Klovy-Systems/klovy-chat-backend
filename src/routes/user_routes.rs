use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::user_controller::get_user_status;
use crate::middlewares::auth_middleware::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/status/{userId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_status)),
    );
    cfg.service(
        web::resource("/{userId}/status")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_status)),
    );
}
