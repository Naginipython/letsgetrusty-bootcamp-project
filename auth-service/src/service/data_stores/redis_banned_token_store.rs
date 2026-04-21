use std::sync::Arc;

use redis::{Connection, TypedCommands};
use tokio::sync::RwLock;

use crate::{domain::{BannedTokenStore, BannedTokenStoreError}, utils::auth::TOKEN_TTL_SECONDS};

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        if let Ok(true) = self.token_exists(token).await {
            return Err(BannedTokenStoreError::TokenExists)
        }
        let key = get_key(token);
        self.conn.write()
            .await
            .set_ex(key, true, TOKEN_TTL_SECONDS as u64)
            .map_err(|_|BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }
    
    async fn token_exists(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);
        self.conn.write().await.exists(key).map_err(|_| BannedTokenStoreError::UnexpectedError)
    }
}

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{get_redis_client, utils::constants::REDIS_HOST_NAME};

    use super::*;
    
    fn create_store() -> RedisBannedTokenStore {
        let config = get_redis_client(REDIS_HOST_NAME.to_owned())
            .expect("Failed to get Redis client")
            .get_connection()
            .expect("Failed to get Redis connection");
        let conn = Arc::new(RwLock::new(config));
        RedisBannedTokenStore::new(conn)
    }

    #[tokio::test]
    async fn adding_to_store_doesnt_result_in_err() {
        let mut map = create_store();
        let token = Uuid::new_v4();
        let result = map.store_token(&token.to_string()).await;
        assert!(result.is_ok())
    }

    #[tokio::test]
    async fn cant_add_token_if_already_exists() {
        let mut map = create_store();
        let token = Uuid::new_v4();
        let result = map.store_token(&token.to_string().clone()).await;
        assert!(result.is_ok());
        let result = map.store_token(&token.to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn token_exist_true_test() {
        let mut map = create_store();
        let _ = map.store_token("12345").await;

        let result = map.token_exists("12345").await;
        assert_eq!(Ok(true), result);
    }

    #[tokio::test]
    async fn token_exists_false_test() {
        let mut map = create_store();
        let _ = map.store_token("12345").await;

        let result = map.token_exists("6789").await;
        assert_eq!(Ok(false), result);
    }
}