// emojis.rs
// Routing emoji proxy.
// Zakres:
//  - GET
//  - GET proxy; rate limit jak inne auth
// Rate limit jak inne public+auth.
// Przy zmianach: controllers/emojis.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::emojis::get_emojis;
use crate::middlewares::auth::{require_active_account, verify_token};

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
