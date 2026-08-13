use std::collections::{HashMap, HashSet};

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::badge_model::Badge;
use crate::model::user_model::{User, UserBadge};

fn iso(dt: &mongodb::bson::DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BadgeVisibility {
    All,
    Featured,
}

pub fn ensure_badge_ids(badges: &mut [UserBadge]) -> bool {
    let mut changed = false;
    for badge in badges.iter_mut() {
        if badge.id.is_none() {
            badge.id = Some(ObjectId::new());
            changed = true;
        }
    }
    changed
}

/// Każdy typ odznaki (badgeId) może wystąpić u użytkownika tylko raz.
pub fn user_has_badge_id(badges: &[UserBadge], badge_id: ObjectId) -> bool {
    badges.iter().any(|badge| badge.badge_id == badge_id)
}

/// Usuwa zduplikowane przypisania tego samego typu odznaki (zostawia najstarsze).
pub fn dedupe_user_badges(badges: &mut Vec<UserBadge>) -> bool {
    let mut seen = HashSet::new();
    let before = badges.len();
    badges.retain(|badge| seen.insert(badge.badge_id));
    badges.len() != before
}

fn badges_for_visibility<'a>(user: &'a User, visibility: BadgeVisibility) -> Vec<&'a UserBadge> {
    match visibility {
        BadgeVisibility::All => user.badges.iter().collect(),
        BadgeVisibility::Featured => {
            if user.featured_badge_ids.is_empty() {
                user.badges.iter().collect()
            } else {
                let featured: HashSet<_> = user.featured_badge_ids.iter().collect();
                user.badges
                    .iter()
                    .filter(|badge| {
                        badge
                            .id
                            .as_ref()
                            .map(|id| featured.contains(id))
                            .unwrap_or(false)
                    })
                    .collect()
            }
        }
    }
}

fn user_badge_to_json(user_badge: &UserBadge, badge: &Badge) -> Value {
    json!({
        "_id": user_badge.id.map(|o| o.to_hex()),
        "badgeId": {
            "_id": badge.id.map(|o| o.to_hex()),
            "name": badge.name,
            "icon": badge.icon,
            "color": badge.color,
            "description": badge.description,
            "createdAt": iso(&badge.created_at),
            "updatedAt": iso(&badge.updated_at),
        },
        "assignedAt": iso(&user_badge.assigned_at),
    })
}

pub async fn populate_user_badge_entry(db: &Database, user_badge: &UserBadge) -> Option<Value> {
    let badge = match Badge::find_by_id(db, user_badge.badge_id).await {
        Ok(Some(b)) => b,
        Ok(None) | Err(_) => return None,
    };
    Some(user_badge_to_json(user_badge, &badge))
}

/// Batch-load badge documents for many users (contact list / channel member enrichment).
pub async fn load_badges_by_ids(
    db: &Database,
    ids: impl IntoIterator<Item = ObjectId>,
) -> HashMap<ObjectId, Badge> {
    let ids: Vec<ObjectId> = {
        let mut seen = HashSet::new();
        ids.into_iter().filter(|id| seen.insert(*id)).collect()
    };
    let mut map = HashMap::new();
    if ids.is_empty() {
        return map;
    }
    match Badge::collection(db).find(doc! { "_id": { "$in": &ids } }).await {
        Ok(cursor) => match cursor.try_collect::<Vec<Badge>>().await {
            Ok(badges) => {
                for badge in badges {
                    if let Some(id) = badge.id {
                        map.insert(id, badge);
                    }
                }
            }
            // Fail soft for display-only badges — log so ops can see hydrate pressure.
            Err(e) => log::warn!("load_badges_by_ids try_collect: {e}"),
        },
        Err(e) => log::warn!("load_badges_by_ids find: {e}"),
    }
    map
}

pub fn populate_user_badges_from_map(
    user: &User,
    visibility: BadgeVisibility,
    badges: &HashMap<ObjectId, Badge>,
) -> Vec<Value> {
    badges_for_visibility(user, visibility)
        .into_iter()
        .filter_map(|user_badge| {
            badges
                .get(&user_badge.badge_id)
                .map(|badge| user_badge_to_json(user_badge, badge))
        })
        .collect()
}

pub async fn populate_user_badges(
    db: &Database,
    user: &User,
    visibility: BadgeVisibility,
) -> Vec<Value> {
    let ids: Vec<ObjectId> = badges_for_visibility(user, visibility)
        .into_iter()
        .map(|b| b.badge_id)
        .collect();
    let map = load_badges_by_ids(db, ids).await;
    populate_user_badges_from_map(user, visibility, &map)
}

pub fn featured_badge_ids_for_response(user: &User) -> Vec<String> {
    user.featured_badge_ids
        .iter()
        .map(|id| id.to_hex())
        .collect()
}
