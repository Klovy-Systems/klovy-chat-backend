use klovy_chat_server::loaders::express;
use klovy_chat_server::utils::app_env::is_production;
use klovy_chat_server::model::{
    announcement_model::Announcement, audit_log_model::AuditLog, channel_model::Channel,
    channel_read_state_model::ChannelReadState, channel_report_model::ChannelReport,
    e2e_keys_model::E2eKeyBundle, friend_request_model::FriendRequest, invite_model::Invite,
    messages_model::Message, oauth_token_model::OauthToken, pending_upload_model::PendingUpload,
    push_token_model::PushToken, refresh_token_model::RefreshToken, user_model::User, user_storage_usage_model::UserStorageUsage,
    warning_model::Warning,
};
use klovy_chat_server::utils::database_url::database_url;
use klovy_chat_server::utils::db;
use klovy_chat_server::utils::storage::reconcile_attachments;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv_override().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let database_url = database_url().expect("Database URL is not configured");

    db::init_db(&database_url)
        .await
        .expect("Failed to connect to MongoDB");

    db::sync_user_indexes().await.ok();

    klovy_chat_server::utils::config_validate::validate_startup_config();

    klovy_chat_server::utils::storage::init_storage().unwrap_or_else(|e| {
        panic!(
            "Failed to initialize R2 storage: {e}\n\
             Configure R2_* variables in backend/.env — see backend/docs/R2_SETUP.md"
        )
    });

    let mongodb_db = db::get_db();
    ensure_indexes(&mongodb_db).await;

    match PendingUpload::cleanup_orphans(&mongodb_db).await {
        Ok(removed) if removed > 0 => {
            log::info!("Cleaned up {removed} orphaned pending uploads at startup");
        }
        Err(e) => log::warn!("Pending upload cleanup failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::repair_broken_account_status_fields(&mongodb_db).await {
        Ok(repaired) if repaired > 0 => {
            log::info!("Startup: repaired {repaired} user account(s) with invalid isDisabled=null");
        }
        Err(e) => log::warn!("Startup account status repair failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::reconcile_whitelist_fields(&mongodb_db).await {
        Ok((legacy, admins)) if legacy > 0 || admins > 0 => {
            log::info!(
                "Startup whitelist reconcile: approved {legacy} legacy account(s), {admins} admin account(s)"
            );
        }
        Err(e) => log::warn!("Startup whitelist reconcile failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::process_scheduled_deletions(&mongodb_db).await {
        Ok(deleted) if deleted > 0 => {
            log::info!("Startup: auto-deleted {deleted} scheduled user account(s)");
        }
        Err(e) => log::warn!("Startup scheduled account deletion failed: {e}"),
        _ => {}
    }

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(6 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match PendingUpload::cleanup_orphans(&db).await {
                Ok(removed) if removed > 0 => {
                    log::info!("Periodic cleanup removed {removed} orphaned pending uploads");
                }
                Err(e) => log::warn!("Periodic pending upload cleanup failed: {e}"),
                _ => {}
            }
        }
    });

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match klovy_chat_server::utils::admin::process_scheduled_deletions(&db).await {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Auto-deleted {deleted} scheduled user account(s)");
                }
                Err(e) => log::warn!("Scheduled account deletion job failed: {e}"),
                _ => {}
            }
        }
    });

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(24 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match reconcile_attachments(&db).await {
                Ok(report) if report.orphan_objects_deleted > 0 || report.missing_objects > 0 => {
                    log::info!(
                        "Attachment reconcile: deleted {} orphan R2 objects, {} missing in R2, {} usage records updated",
                        report.orphan_objects_deleted,
                        report.missing_objects,
                        report.usage_users_updated
                    );
                }
                Ok(report) if report.usage_users_updated > 0 => {
                    log::info!(
                        "Attachment reconcile: rebuilt storage usage for {} users",
                        report.usage_users_updated
                    );
                }
                Err(e) => log::warn!("Attachment reconcile failed: {e}"),
                _ => {}
            }
        }
    });

    match reconcile_attachments(&mongodb_db).await {
        Ok(report) => log::info!(
            "Startup attachment reconcile: deleted {} orphan R2 objects, {} missing in R2, {} usage records updated",
            report.orphan_objects_deleted,
            report.missing_objects,
            report.usage_users_updated
        ),
        Err(e) => log::warn!("Startup attachment reconcile failed: {e}"),
    }

    log::info!(
        "Klovy Chat server startup (whitelist: {})",
        if klovy_chat_server::utils::whitelist::is_whitelist_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );
    express::run_server().await
}

async fn ensure_indexes(db: &mongodb::Database) {
    let tasks: [(&str, mongodb::error::Result<()>); 17] = [
        ("users", User::create_indexes(db).await),
        ("signup_quotas", klovy_chat_server::utils::registration::create_indexes(db).await),
        ("channels", Channel::create_indexes(db).await),
        ("messages", Message::create_indexes(db).await),
        ("e2e_keys", E2eKeyBundle::create_indexes(db).await),
        ("friend_requests", FriendRequest::create_indexes(db).await),
        ("invites", Invite::create_indexes(db).await),
        ("channel_read_states", ChannelReadState::create_indexes(db).await),
        ("channel_reports", ChannelReport::create_indexes(db).await),
        ("refresh_tokens", RefreshToken::create_indexes(db).await),
        ("oauth_tokens", OauthToken::create_indexes(db).await),
        ("push_tokens", PushToken::create_indexes(db).await),
        ("pending_uploads", PendingUpload::create_indexes(db).await),
        ("user_storage_usage", UserStorageUsage::create_indexes(db).await),
        ("audit_logs", AuditLog::create_indexes(db).await),
        ("warnings", Warning::create_indexes(db).await),
        ("announcements", Announcement::create_indexes(db).await),
    ];

    for (name, result) in tasks {
        if let Err(error) = result {
            log::error!("Failed to create MongoDB indexes for {name}: {error}");
            if is_production() {
                panic!("MongoDB index creation failed for {name}: {error}");
            }
        }
    }
}
