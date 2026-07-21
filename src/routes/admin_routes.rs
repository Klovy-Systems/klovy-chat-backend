use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::admin_controller::{
    admin_logout, admin_session_status, assign_badge, block_user, create_badge,
    delete_badge, delete_channel_admin, delete_channel_report, delete_user, delete_user_warning,
    get_user_badges, list_badges, list_channel_reports, list_channels, list_user_warnings,
    list_users, remove_badge, restore_user, set_user_password, set_user_whitelist, unblock_user,
    update_badge, update_channel_report_status, warn_user,
};
use crate::controllers::announcement_controller::{
    create_announcement, delete_announcement, list_admin_announcements, update_announcement,
};
use crate::middlewares::admin_auth_middleware::{check_admin_configured, verify_admin_session};
use crate::middlewares::validation_middleware::validate_password;
use crate::utils::ratelimit::admin_action_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(check_admin_configured))
            .route(web::get().to(admin_session_status)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(check_admin_configured))
            .route(web::get().to(admin_session_status)),
    );

    cfg.service(
        web::resource("/session")
            .wrap(from_fn(check_admin_configured))
            .route(web::get().to(admin_session_status)),
    );

    cfg.service(
        web::resource("/logout")
            .wrap(from_fn(verify_admin_session))
            .route(web::post().to(admin_logout)),
    );

    cfg.service(
        web::scope("")
            .wrap(from_fn(admin_action_limiter))
            .wrap(from_fn(verify_admin_session))
            .service(web::resource("/users").route(web::get().to(list_users)))
            .service(
                web::resource("/users/{userId}/block").route(web::patch().to(block_user)),
            )
            .service(
                web::resource("/users/{userId}/unblock").route(web::patch().to(unblock_user)),
            )
            .service(
                web::resource("/users/{userId}/restore").route(web::patch().to(restore_user)),
            )
            .service(
                web::resource("/users/{userId}/whitelist")
                    .route(web::patch().to(set_user_whitelist)),
            )
            .service(
                web::resource("/users/{userId}/password")
                    .wrap(from_fn(validate_password))
                    .route(web::patch().to(set_user_password)),
            )
            .service(web::resource("/users/{userId}").route(web::delete().to(delete_user)))
            .service(
                web::resource("/users/{userId}/assign-badge").route(web::post().to(assign_badge)),
            )
            .service(
                web::resource("/users/{userId}/badges").route(web::get().to(get_user_badges)),
            )
            .service(
                web::resource("/users/{userId}/badges/{assignmentId}")
                    .route(web::delete().to(remove_badge)),
            )
            .service(
                web::resource("/users/{userId}/warnings")
                    .route(web::get().to(list_user_warnings))
                    .route(web::post().to(warn_user)),
            )
            .service(
                web::resource("/users/{userId}/warnings/{warningId}")
                    .route(web::delete().to(delete_user_warning)),
            )
            .service(web::resource("/channels").route(web::get().to(list_channels)))
            .service(
                web::resource("/channels/{channelId}").route(web::delete().to(delete_channel_admin)),
            )
            .service(web::resource("/reports").route(web::get().to(list_channel_reports)))
            .service(
                web::resource("/reports/{reportId}")
                    .route(web::patch().to(update_channel_report_status))
                    .route(web::delete().to(delete_channel_report)),
            )
            .service(
                web::resource("/badges")
                    .route(web::get().to(list_badges))
                    .route(web::post().to(create_badge)),
            )
            .service(
                web::resource("/badges/{badgeId}")
                    .route(web::put().to(update_badge))
                    .route(web::delete().to(delete_badge)),
            )
            .service(
                web::resource("/announcements")
                    .route(web::get().to(list_admin_announcements))
                    .route(web::post().to(create_announcement)),
            )
            .service(
                web::resource("/announcements/{announcementId}")
                    .route(web::put().to(update_announcement))
                    .route(web::delete().to(delete_announcement)),
            ),
    );
}
