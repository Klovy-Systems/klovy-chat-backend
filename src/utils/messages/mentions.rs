use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use regex::Regex;

use crate::model::user_model::User;

lazy_static::lazy_static! {
    static ref MENTION_REGEX: Regex = Regex::new(
        r"(?i)(?:^|[^A-Za-z0-9_@])@([a-z0-9_]{3,32})(?:$|[^a-z0-9_])"
    )
    .unwrap();
    static ref EVERYONE_REGEX: Regex = Regex::new(
        r"(?i)(?:^|[^A-Za-z0-9_@])@(everyone|here)(?:$|[^a-z0-9_])"
    )
    .unwrap();
}

pub fn extract_mention_usernames(content: &str) -> Vec<String> {
    if content.is_empty() {
        return vec![];
    }
    let mut found = std::collections::HashSet::new();
    for cap in MENTION_REGEX.captures_iter(content) {
        if let Some(name) = cap.get(1) {
            let n = name.as_str().to_lowercase();
            if n != "everyone" && n != "here" {
                found.insert(n);
            }
        }
    }
    found.into_iter().collect()
}

pub fn has_everyone_mention(content: &str) -> bool {
    !content.is_empty() && EVERYONE_REGEX.is_match(content)
}

pub async fn resolve_mentions(
    db: &Database,
    content: &str,
    allowed_user_ids: &[String],
) -> Vec<ObjectId> {
    let usernames = extract_mention_usernames(content);
    if usernames.is_empty() || allowed_user_ids.is_empty() {
        return vec![];
    }

    let allowed: Vec<ObjectId> = allowed_user_ids
        .iter()
        .filter_map(|id| ObjectId::parse_str(id).ok())
        .collect();
    if allowed.is_empty() {
        return vec![];
    }

    let users: Vec<User> = match User::collection(db)
        .find(doc! { "_id": { "$in": &allowed }, "username": { "$in": &usernames } })
        .await
    {
        Ok(c) => futures_util::TryStreamExt::try_collect(c).await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    users.into_iter().filter_map(|u| u.id).collect()
}
