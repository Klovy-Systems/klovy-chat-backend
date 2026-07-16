use actix_web::HttpRequest;
use serde_json::Value;

use crate::model::audit_log_model::AuditLog;
use crate::utils::client_ip::client_ip_from_http_request;
use crate::utils::db::get_db;

pub async fn log_admin_action(
    req: &HttpRequest,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: Value,
) {
    let client_ip = client_ip_from_http_request(req);
    let db = get_db();
    if let Err(e) = AuditLog::insert(
        &db,
        action,
        target_type,
        target_id,
        details,
        Some(&client_ip),
    )
    .await
    {
        log::error!("Failed to write admin audit log ({action}): {e}");
    }
}
