use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::emoji_controller::get_emojis;
use crate::middlewares::auth_middleware::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_emojis)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_emojis)),
    );
}
