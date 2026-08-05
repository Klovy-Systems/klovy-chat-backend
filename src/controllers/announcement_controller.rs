use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::announcement_model::{
    validate_announcement, Announcement, AnnouncementDismissal, CreateAnnouncementInput,
};
use crate::utils::admin_audit::log_admin_action;
use crate::utils::auth::admin_session::require_panel_permission;
use crate::utils::auth::panel_permissions::PanelPermission;
use crate::utils::db::get_db;
use crate::ws::registry::emit_to_all_connected;

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

fn serialize_announcement(a: &Announcement) -> serde_json::Value {
    json!({
        "id": a.id.map(|o| o.to_hex()),
        "title": a.title,
        "body": a.body,
        "active": a.active,
        "createdAt": iso(&a.created_at),
        "updatedAt": iso(&a.updated_at),
    })
}

fn param<'a>(req: &'a HttpRequest, name: &str) -> &'a str {
    req.match_info().get(name).unwrap_or("")
}

fn broadcast_announcement(a: &Announcement) {
    if !a.active {
        return;
    }
    emit_to_all_connected(
        "announcement:published",
        json!({ "announcement": serialize_announcement(a) }),
    );
}

pub async fn list_admin_announcements(req: HttpRequest) -> HttpResponse {
    if let Err(response) =
        require_panel_permission(&req, PanelPermission::ManageAnnouncements).await
    {
        return response;
    }

    let db = get_db();
    match Announcement::list_all(&db).await {
        Ok(items) => HttpResponse::Ok().json(json!({
            "announcements": items.iter().map(serialize_announcement).collect::<Vec<_>>(),
        })),
        Err(e) => {
            log::error!("list_admin_announcements: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać ogłoszeń." }))
        }
    }
}

#[derive(Deserialize)]
pub struct CreateAnnouncementBody {
    pub title: Option<String>,
    pub body: Option<String>,
    pub active: Option<bool>,
}

pub async fn create_announcement(req: HttpRequest, body: web::Json<CreateAnnouncementBody>) -> HttpResponse {
    if let Err(response) =
        require_panel_permission(&req, PanelPermission::ManageAnnouncements).await
    {
        return response;
    }

    let title = body.title.as_deref().unwrap_or("");
    let content = body.body.as_deref().unwrap_or("");
    if let Err(message) = validate_announcement(title, content) {
        return HttpResponse::BadRequest().json(json!({ "error": message }));
    }

    let db = get_db();
    match Announcement::create(
        &db,
        CreateAnnouncementInput {
            title: title.to_string(),
            body: content.to_string(),
            active: body.active.unwrap_or(true),
        },
    )
    .await
    {
        Ok(announcement) => {
            log_admin_action(
                &req,
                "announcement.create",
                Some("announcement"),
                announcement.id.as_ref().map(|o| o.to_hex()).as_deref(),
                json!({ "title": announcement.title, "active": announcement.active }),
            )
            .await;
            broadcast_announcement(&announcement);
            HttpResponse::Created().json(json!({
                "message": "Ogłoszenie zostało opublikowane.",
                "announcement": serialize_announcement(&announcement),
            }))
        }
        Err(e) => {
            log::error!("create_announcement: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się utworzyć ogłoszenia." }))
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAnnouncementBody {
    pub title: Option<String>,
    pub body: Option<String>,
    pub active: Option<bool>,
}

pub async fn update_announcement(
    req: HttpRequest,
    body: web::Json<UpdateAnnouncementBody>,
) -> HttpResponse {
    if let Err(response) =
        require_panel_permission(&req, PanelPermission::ManageAnnouncements).await
    {
        return response;
    }

    let Ok(aid) = ObjectId::parse_str(param(&req, "announcementId")) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe ID ogłoszenia." }));
    };

    let db = get_db();
    let existing = match Announcement::find_by_id(&db, aid).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Ogłoszenie nie istnieje." }));
        }
        Err(e) => {
            log::error!("update_announcement find: {e}");
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się zaktualizować ogłoszenia." }));
        }
    };

    let title = body
        .title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(existing.title.as_str());
    let content = body
        .body
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(existing.body.as_str());
    if let Err(message) = validate_announcement(title, content) {
        return HttpResponse::BadRequest().json(json!({ "error": message }));
    }

    let mut set = doc! {
        "title": title,
        "body": content,
        "updatedAt": DateTime::now(),
    };
    if let Some(active) = body.active {
        set.insert("active", active);
    }

    match Announcement::update_fields(&db, aid, set).await {
        Ok(Some(updated)) => {
            log_admin_action(
                &req,
                "announcement.update",
                Some("announcement"),
                Some(&aid.to_hex()),
                json!({ "title": updated.title, "active": updated.active }),
            )
            .await;
            if updated.active {
                broadcast_announcement(&updated);
            }
            HttpResponse::Ok().json(json!({
                "message": "Ogłoszenie zostało zaktualizowane.",
                "announcement": serialize_announcement(&updated),
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "Ogłoszenie nie istnieje." })),
        Err(e) => {
            log::error!("update_announcement: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się zaktualizować ogłoszenia." }))
        }
    }
}

pub async fn delete_announcement(req: HttpRequest) -> HttpResponse {
    if let Err(response) =
        require_panel_permission(&req, PanelPermission::ManageAnnouncements).await
    {
        return response;
    }

    let Ok(aid) = ObjectId::parse_str(param(&req, "announcementId")) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe ID ogłoszenia." }));
    };

    let db = get_db();
    match Announcement::delete_by_id(&db, aid).await {
        Ok(true) => {
            log_admin_action(
                &req,
                "announcement.delete",
                Some("announcement"),
                Some(&aid.to_hex()),
                json!({}),
            )
            .await;
            HttpResponse::Ok().json(json!({ "message": "Ogłoszenie zostało usunięte." }))
        }
        Ok(false) => HttpResponse::NotFound().json(json!({ "error": "Ogłoszenie nie istnieje." })),
        Err(e) => {
            log::error!("delete_announcement: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się usunąć ogłoszenia." }))
        }
    }
}

pub async fn get_my_announcements(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id." }));
    };

    let db = get_db();
    let active = match Announcement::list_active(&db).await {
        Ok(items) => items,
        Err(e) => {
            log::error!("get_my_announcements list: {e}");
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać ogłoszeń." }));
        }
    };

    let dismissed = AnnouncementDismissal::dismissed_ids_for_user(&db, uid)
        .await
        .unwrap_or_default();
    let unread: Vec<_> = active
        .into_iter()
        .filter(|a| a.id.map(|id| !dismissed.contains(&id)).unwrap_or(false))
        .map(|a| serialize_announcement(&a))
        .collect();

    HttpResponse::Ok().json(json!({
        "announcements": unread,
        "total": unread.len(),
    }))
}

#[derive(Deserialize)]
pub struct DismissAnnouncementsBody {
    #[serde(rename = "announcementIds")]
    pub announcement_ids: Option<Vec<String>>,
}

pub async fn dismiss_announcements(req: HttpRequest, body: web::Json<DismissAnnouncementsBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id." }));
    };

    let ids: Vec<ObjectId> = body
        .announcement_ids
        .as_ref()
        .map(|list| {
            list.iter()
                .filter_map(|s| ObjectId::parse_str(s.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    if ids.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Brak ogłoszeń do zamknięcia." }));
    }

    let db = get_db();
    match AnnouncementDismissal::dismiss_all(&db, uid, &ids).await {
        Ok(count) => HttpResponse::Ok().json(json!({
            "message": "Ogłoszenia zostały zamknięte.",
            "dismissed": count,
        })),
        Err(e) => {
            log::error!("dismiss_announcements: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się zamknąć ogłoszeń." }))
        }
    }
}
