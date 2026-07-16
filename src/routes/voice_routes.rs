use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::voice_controller::get_voice_token;
use crate::middlewares::auth_middleware::{
    log_suspicious_activity, require_active_account, verify_token,
};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(log_suspicious_activity("voice-token")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_voice_token)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(log_suspicious_activity("voice-token")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_voice_token)),
    );
    cfg.service(
        web::resource("/token")
            .wrap(from_fn(log_suspicious_activity("voice-token")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_voice_token)),
    );
    cfg.service(
        web::resource("/call/token")
            .wrap(from_fn(log_suspicious_activity("voice-token")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_voice_token)),
    );
}
