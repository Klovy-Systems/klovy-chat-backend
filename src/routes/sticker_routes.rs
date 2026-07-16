use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::sticker_controller::{search_stickers, trending_stickers};
use crate::middlewares::auth_middleware::{
    log_suspicious_activity, require_active_account, verify_token,
};
use crate::utils::ratelimit::discovery_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(log_suspicious_activity("sticker-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_stickers)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(log_suspicious_activity("sticker-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_stickers)),
    );
    cfg.service(
        web::resource("/trending")
            .wrap(from_fn(log_suspicious_activity("sticker-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_stickers)),
    );
    cfg.service(
        web::resource("/trends")
            .wrap(from_fn(log_suspicious_activity("sticker-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_stickers)),
    );
    cfg.service(
        web::resource("/search")
            .wrap(from_fn(log_suspicious_activity("sticker-search")))
            .wrap(from_fn(discovery_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(search_stickers)),
    );
}
