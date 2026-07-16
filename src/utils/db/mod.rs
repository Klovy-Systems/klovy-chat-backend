use mongodb::{Client, Database};
use once_cell::sync::OnceCell;

static DB: OnceCell<Database> = OnceCell::new();

pub async fn init_db(uri: &str) -> mongodb::error::Result<()> {
    let mut options = mongodb::options::ClientOptions::parse(uri).await?;
    options.max_pool_size = Some(10);
    options.server_selection_timeout = Some(std::time::Duration::from_secs(10));
    options.connect_timeout = Some(std::time::Duration::from_secs(45));

    let client = Client::with_options(options)?;

    let db = match client.default_database() {
        Some(db) => db,
        None => {
            let name = std::env::var("DB_NAME").unwrap_or_else(|_| "klovy".to_string());
            client.database(&name)
        }
    };

    db.run_command(mongodb::bson::doc! { "ping": 1 }).await?;

    let _ = DB.set(db);
    Ok(())
}

pub fn get_db() -> Database {
    DB.get()
        .expect("Database not initialized — call init_db() first")
        .clone()
}

pub async fn sync_user_indexes() -> mongodb::error::Result<()> {
    const STALE_USER_INDEXES: &[&str] = &["email_1"];

    let db = get_db();
    let collection = db.collection::<mongodb::bson::Document>("users");

    let mut cursor = match collection.list_indexes().await {
        Ok(c) => c,
        Err(_) => {
            log::info!("Users collection does not exist yet — skipping index cleanup");
            return Ok(());
        }
    };

    use futures::stream::StreamExt;
    let mut existing: Vec<String> = Vec::new();
    while let Some(item) = cursor.next().await {
        if let Ok(model) = item {
            if let Some(name) = model.options.and_then(|o| o.name) {
                existing.push(name);
            }
        }
    }

    for stale in STALE_USER_INDEXES {
        if existing.iter().any(|n| n == stale) {
            if let Err(e) = collection.drop_index((*stale).to_string()).await {
                log::error!("Error dropping stale index {}: {}", stale, e);
            } else {
                log::info!("Dropped stale users index: {}", stale);
            }
        }
    }

    Ok(())
}
