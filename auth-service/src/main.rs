use std::sync::Arc;

use auth_service::{Application, app_state::AppState, service::{HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore, mock_email_client::MockEmailClient}, utils::constants::prod};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient::default()));
    let app_state = AppState::new(user_store, banned_store, two_fa_code_store, email_client);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");
            
    app.run().await.expect("Failed to run app");
}
