use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::status_controller::update_user_status;
use crate::middlewares::auth_middleware::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(update_user_status)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(update_user_status)),
    );
    cfg.service(
        web::resource("/update")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(update_user_status)),
    );
}
