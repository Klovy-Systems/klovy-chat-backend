use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::bot_controller::{
    bot_me, bot_send_channel_message, create_bot, delete_bot, list_my_bots,
    regenerate_bot_token, update_bot,
};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};
use crate::middlewares::bot_auth_middleware::verify_bot_token;

/// Zarządzanie botami (`/api/bots`) — auth ciasteczkiem właściciela.
pub fn configure_management(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(list_my_bots))
            .route(web::post().to(create_bot)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(list_my_bots))
            .route(web::post().to(create_bot)),
    );
    cfg.service(
        web::resource("/{botId}/token")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(regenerate_bot_token)),
    );
    cfg.service(
        web::resource("/{botId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(update_bot))
            .route(web::delete().to(delete_bot)),
    );
}

/// Runtime botów (`/api/bot`) — auth nagłówkiem `Authorization: Bearer`.
pub fn configure_runtime(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/me")
            .wrap(from_fn(verify_bot_token))
            .route(web::get().to(bot_me)),
    );
    cfg.service(
        web::resource("/channels/{channelId}/messages")
            .wrap(from_fn(verify_bot_token))
            .route(web::post().to(bot_send_channel_message)),
    );
}
