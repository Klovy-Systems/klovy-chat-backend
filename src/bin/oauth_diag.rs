use klovy_chat_server::utils::database_url::database_url;
use klovy_chat_server::utils::db;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = database_url().expect("DATABASE_URL is not configured");
    db::init_db(&database_url)
        .await
        .expect("Failed to connect to MongoDB");

    let database = db::get_db();
    let collection = database.collection::<mongodb::bson::Document>("oauth_tokens");

    let count = collection
        .count_documents(mongodb::bson::doc! {})
        .await
        .unwrap_or(0);

    println!("oauth_tokens count: {count}");

    if count > 0 {
        let mut cursor = collection
            .find(mongodb::bson::doc! {})
            .projection(mongodb::bson::doc! {
                "userId": 1,
                "provider": 1,
                "createdAt": 1,
                "updatedAt": 1,
            })
            .await
            .expect("find oauth_tokens");

        use futures::stream::StreamExt;
        while let Some(doc) = cursor.next().await {
            if let Ok(doc) = doc {
                println!("{doc:?}");
            }
        }
    }
}
