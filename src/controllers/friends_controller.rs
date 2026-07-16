use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::friend_request_model::{FriendRequest, FriendRequestStatus};
use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::friends::{are_friends, map_friend_user};
use crate::utils::validators::normalize_username::normalize_username;
use crate::utils::whitelist::is_whitelist_enabled;

const FRIEND_REQUEST_UNAVAILABLE: &str = "Nie można wysłać zaproszenia do tego użytkownika.";

fn recipient_available(user: &User) -> bool {
    if !user.is_login_allowed() || user.is_bot {
        return false;
    }
    !is_whitelist_enabled() || user.is_whitelisted
}

fn status_str(status: &FriendRequestStatus) -> &'static str {
    match status {
        FriendRequestStatus::Pending => "pending",
        FriendRequestStatus::Accepted => "accepted",
        FriendRequestStatus::Rejected => "rejected",
    }
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

#[derive(Deserialize)]
pub struct SendFriendRequestBody {
    pub username: Option<String>,
}

pub async fn send_friend_request(
    req: HttpRequest,
    body: web::Json<SendFriendRequestBody>,
) -> HttpResponse {
    let Some(sender_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(sender_oid) = ObjectId::parse_str(&sender_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let raw = body.username.clone().unwrap_or_default();
    if raw.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Podaj nazwę użytkownika (@username)." }));
    }
    let username = normalize_username(&raw);
    if username.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowa nazwa użytkownika." }));
    }

    let db = get_db();
    let recipient = match User::find_by_username(&db, &username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::BadRequest().json(json!({
                "error": FRIEND_REQUEST_UNAVAILABLE
            }))
        }
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let recipient_oid = match recipient.id {
        Some(o) => o,
        None => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };
    let recipient_id = recipient_oid.to_hex();

    if !recipient_available(&recipient) {
        return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
    }

    if recipient_id == sender_id {
        return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
    }

    if are_friends(&db, &sender_id, &recipient_id).await {
        return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
    }

    let col = FriendRequest::collection(&db);
    let existing = col
        .find_one(doc! {
            "$or": [
                { "from": sender_oid, "to": recipient_oid },
                { "from": recipient_oid, "to": sender_oid },
            ]
        })
        .await
        .ok()
        .flatten();

    if let Some(existing) = existing {
        let existing_id = existing.id.unwrap_or_default();
        match existing.status {
            FriendRequestStatus::Accepted => {
                return HttpResponse::BadRequest()
                    .json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
            }
            FriendRequestStatus::Pending => {
                if existing.from == recipient_oid {
                    let _ = col
                        .update_one(
                            doc! { "_id": existing_id },
                            doc! { "$set": { "status": "accepted", "updatedAt": DateTime::now() } },
                        )
                        .await;
                    return HttpResponse::Ok().json(json!({
                        "message": "Wzajemne zaproszenie — jesteście teraz znajomymi.",
                        "autoAccepted": true,
                        "friend": map_friend_user(&recipient),
                    }));
                }
                return HttpResponse::BadRequest().json(json!({
                    "error": FRIEND_REQUEST_UNAVAILABLE
                }));
            }
            FriendRequestStatus::Rejected => {
                let now = DateTime::now();
                let _ = col
                    .update_one(
                        doc! { "_id": existing_id },
                        doc! { "$set": {
                            "from": sender_oid,
                            "to": recipient_oid,
                            "status": "pending",
                            "updatedAt": now,
                        }},
                    )
                    .await;
                return HttpResponse::Ok().json(json!({
                    "message": "Zaproszenie wysłane.",
                    "request": {
                        "_id": existing_id.to_hex(),
                        "to": map_friend_user(&recipient),
                        "status": "pending",
                        "createdAt": iso(&existing.created_at),
                    }
                }));
            }
        }
    }

    match FriendRequest::create(&db, sender_oid, recipient_oid).await {
        Ok(request) => HttpResponse::Created().json(json!({
            "message": "Zaproszenie wysłane.",
            "request": {
                "_id": request.id.map(|o| o.to_hex()),
                "to": map_friend_user(&recipient),
                "status": "pending",
                "createdAt": iso(&request.created_at),
            }
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    }
}

pub async fn get_received_requests(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let requests: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "to": uid, "status": "pending" })
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let mut out = Vec::new();
    for r in &requests {
        if let Ok(Some(from_user)) = User::find_by_id(&db, r.from).await {
            out.push(json!({
                "_id": r.id.map(|o| o.to_hex()),
                "from": map_friend_user(&from_user),
                "status": status_str(&r.status),
                "createdAt": iso(&r.created_at),
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "requests": out }))
}

pub async fn get_sent_requests(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let requests: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "from": uid, "status": "pending" })
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let mut out = Vec::new();
    for r in &requests {
        if let Ok(Some(to_user)) = User::find_by_id(&db, r.to).await {
            out.push(json!({
                "_id": r.id.map(|o| o.to_hex()),
                "to": map_friend_user(&to_user),
                "status": status_str(&r.status),
                "createdAt": iso(&r.created_at),
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "requests": out }))
}

pub async fn accept_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.to.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    let _ = col
        .update_one(
            doc! { "_id": rid },
            doc! { "$set": { "status": "accepted", "updatedAt": DateTime::now() } },
        )
        .await;

    let from_user = match User::find_by_id(&db, request.from).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    HttpResponse::Ok().json(json!({
        "message": "Zaproszenie zaakceptowane.",
        "friend": map_friend_user(&from_user),
    }))
}

pub async fn reject_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.to.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    let _ = col
        .update_one(
            doc! { "_id": rid },
            doc! { "$set": { "status": "rejected", "updatedAt": DateTime::now() } },
        )
        .await;

    HttpResponse::Ok().json(json!({ "message": "Zaproszenie odrzucone." }))
}

pub async fn cancel_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.from.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    let _ = col
        .update_one(
            doc! { "_id": rid },
            doc! { "$set": { "status": "rejected", "updatedAt": DateTime::now() } },
        )
        .await;

    HttpResponse::Ok().json(json!({ "message": "Zaproszenie anulowane." }))
}

pub async fn get_friends(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let friendships: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "status": "accepted", "$or": [ { "from": uid }, { "to": uid } ] })
        .sort(doc! { "updatedAt": -1 })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let mut friends = Vec::new();
    for f in &friendships {
        let other_id = if f.from == uid { f.to } else { f.from };
        if let Ok(Some(other)) = User::find_by_id(&db, other_id).await {
            friends.push(map_friend_user(&other));
        }
    }

    HttpResponse::Ok().json(json!({ "friends": friends }))
}

pub async fn check_friendship(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let other_user_id = req.match_info().get("otherUserId").unwrap_or("");
    let Ok(other) = ObjectId::parse_str(other_user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };

    let db = get_db();

    let other_user = match User::find_by_id(&db, other).await {
        Ok(Some(_)) => true,
        _ => false,
    };
    if !other_user {
        return HttpResponse::Ok().json(json!({ "isFriend": false, "pendingRequest": null }));
    }

    let is_friend = are_friends(&db, &user_id, other_user_id).await;

    let mut is_blocked_by_me = false;
    let mut is_blocked_by_other = false;
    if is_friend {
        if let (Ok(Some(me)), Ok(Some(other_user_doc))) =
            (User::find_by_id(&db, uid).await, User::find_by_id(&db, other).await)
        {
            is_blocked_by_me = me
                .blocked_contacts
                .iter()
                .any(|id| *id == other);
            is_blocked_by_other = other_user_doc
                .blocked_contacts
                .iter()
                .any(|id| *id == uid);
        }
    }

    let mut pending_request = serde_json::Value::Null;

    if !is_friend {
        let col = FriendRequest::collection(&db);
        if let Ok(Some(incoming)) = col
            .find_one(doc! { "from": other, "to": uid, "status": "pending" })
            .await
        {
            pending_request = json!({
                "direction": "incoming",
                "requestId": incoming.id.map(|o| o.to_hex()),
            });
        } else if let Ok(Some(outgoing)) = col
            .find_one(doc! { "from": uid, "to": other, "status": "pending" })
            .await
        {
            pending_request = json!({
                "direction": "outgoing",
                "requestId": outgoing.id.map(|o| o.to_hex()),
            });
        }
    }

    HttpResponse::Ok().json(json!({
        "isFriend": is_friend,
        "isBlockedByMe": is_blocked_by_me,
        "isBlockedByOther": is_blocked_by_other,
        "isDmBlocked": is_blocked_by_me || is_blocked_by_other,
        "pendingRequest": pending_request
    }))
}

pub async fn remove_friend(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let friend_user_id = req.match_info().get("friendUserId").unwrap_or("");
    let Ok(friend_oid) = ObjectId::parse_str(friend_user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };
    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };

    if friend_user_id == user_id {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nie możesz usunąć siebie z kontaktów." }));
    }

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let friendship = col
        .find_one(doc! {
            "status": "accepted",
            "$or": [
                { "from": user_oid, "to": friend_oid },
                { "from": friend_oid, "to": user_oid },
            ]
        })
        .await
        .ok()
        .flatten();

    let Some(friendship) = friendship else {
        return HttpResponse::NotFound()
            .json(json!({ "error": "Ten użytkownik nie jest w Twoich kontaktach." }));
    };

    let _ = col.delete_one(doc! { "_id": friendship.id.unwrap_or_default() }).await;

    let _ = db
        .collection::<mongodb::bson::Document>("messages")
        .delete_many(doc! {
            "$or": [
                { "sender": user_oid, "recipient": friend_oid },
                { "sender": friend_oid, "recipient": user_oid },
            ]
        })
        .await;

    HttpResponse::Ok().json(json!({ "message": "Kontakt został usunięty." }))
}
