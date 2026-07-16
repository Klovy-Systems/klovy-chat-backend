use klovy_chat_server::utils::crypto::credential_hash::hash_user_password;

#[tokio::main]
async fn main() {
    let password = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("Usage: cargo run --bin hash-admin-password -- <password>");
            std::process::exit(1);
        });

    match hash_user_password(&password).await {
        Ok(hash) => println!("{hash}"),
        Err(e) => {
            eprintln!("Failed to hash password: {e}");
            std::process::exit(1);
        }
    }
}
