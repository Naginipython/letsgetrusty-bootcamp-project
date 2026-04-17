use std::sync::Arc;

use auth_service::{Application, app_state::AppState, get_postgres_pool, service::{data_stores::{HashmapTwoFACodeStore, HashsetBannedTokenStore, postgres_user_store::PostgresUserStore}, mock_email_client::MockEmailClient}, utils::constants::{DATABASE_URL, prod}};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    
    // let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient::default()));
    let app_state = AppState::new(user_store, banned_store, two_fa_code_store, email_client);

    
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");
            
    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");
    
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");
    
    pg_pool
}