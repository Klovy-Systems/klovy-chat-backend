use std::collections::HashSet;

use mongodb::bson::oid::ObjectId;
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

pub async fn populate_user_badges(
    db: &Database,
    user: &User,
    visibility: BadgeVisibility,
) -> Vec<Value> {
    let mut result = Vec::new();
    for user_badge in badges_for_visibility(user, visibility) {
        if let Ok(Some(badge)) = Badge::find_by_id(db, user_badge.badge_id).await {
            result.push(json!({
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
            }));
        }
    }
    result
}

pub fn featured_badge_ids_for_response(user: &User) -> Vec<String> {
    user.featured_badge_ids
        .iter()
        .map(|id| id.to_hex())
        .collect()
}
