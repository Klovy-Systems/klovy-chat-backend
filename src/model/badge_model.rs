use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Badge {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,

    pub icon: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBadgeInput {
    pub name: String,
    pub icon: String,
    pub color: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug)]
pub enum BadgeValidationError {
    NameRequired,
    NameTooLong,
    IconRequired,
    InvalidColor,
    DescriptionTooLong,
}

impl std::fmt::Display for BadgeValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::NameRequired       => "Badge name is required",
            Self::NameTooLong        => "Badge name must be at most 50 characters",
            Self::IconRequired       => "Badge icon is required",
            Self::InvalidColor       => "Color must be a valid hex color",
            Self::DescriptionTooLong => "Description must be at most 200 characters",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for BadgeValidationError {}

pub fn validate_badge(input: &CreateBadgeInput) -> Result<(), BadgeValidationError> {
    lazy_static::lazy_static! {
        static ref HEX_COLOR: Regex = Regex::new(r"^#[0-9A-Fa-f]{6}$").unwrap();
    }

    if input.name.trim().is_empty() {
        return Err(BadgeValidationError::NameRequired);
    }
    if input.name.trim().len() > 50 {
        return Err(BadgeValidationError::NameTooLong);
    }
    if input.icon.trim().is_empty() {
        return Err(BadgeValidationError::IconRequired);
    }
    if let Some(color) = &input.color {
        if !color.is_empty() && !HEX_COLOR.is_match(color) {
            return Err(BadgeValidationError::InvalidColor);
        }
    }
    if let Some(desc) = &input.description {
        if desc.trim().len() > 200 {
            return Err(BadgeValidationError::DescriptionTooLong);
        }
    }

    Ok(())
}

impl Badge {
    pub fn collection(db: &Database) -> Collection<Badge> {
        db.collection("badges")
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Badge>> {
        Self::collection(db)
            .find_one(doc! { "_id": id })
            .await
    }

    pub async fn find_by_name(
        db: &Database,
        name: &str,
    ) -> mongodb::error::Result<Option<Badge>> {
        Self::collection(db)
            .find_one(doc! { "name": name })
            .await
    }

    pub async fn create(
        db: &Database,
        input: CreateBadgeInput,
    ) -> Result<Badge, Box<dyn std::error::Error>> {
        validate_badge(&input)?;

        let now = DateTime::now();
        let badge = Badge {
            id: None,
            name: input.name.trim().to_string(),
            icon: input.icon.trim().to_string(),
            color: input.color.filter(|c| !c.is_empty()),
            description: input.description.map(|d| d.trim().to_string()).filter(|d| !d.is_empty()),
            created_at: now,
            updated_at: now,
        };

        let result = Self::collection(db).insert_one(&badge).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Badge { id, ..badge })
    }
}