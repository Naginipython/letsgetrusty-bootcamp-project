use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Connection, TypedCommands};
use tokio::sync::RwLock;
use secrecy::{ExposeSecret, SecretString};

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
    #[tracing::instrument(name = "Store token in Redis", skip_all)]
    async fn store_token(&mut self, token: &SecretString) -> Result<(), BannedTokenStoreError> {
        let key = get_key(token);
        
        let ttl = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64")
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        
        self.conn.write()
            .await
            .set_ex(key, true, ttl)
            .wrap_err("failed to set banned token in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }
    
    #[tracing::instrument(name = "Check if token exists in Redis", skip_all)]
    async fn token_exists(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);
        let is_banned = self.conn
            .write()
            .await
            .exists(key)
            .wrap_err("failed to check if token exists in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        
        Ok(is_banned)
    }
}

fn get_key(token: &SecretString) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token.expose_secret())
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
        let token = SecretString::new(Uuid::new_v4().to_string().into_boxed_str());
        let result = map.store_token(&token).await;
        assert!(result.is_ok())
    }

    // #[tokio::test]
    // async fn cant_add_token_if_already_exists() {
    //     let mut map = create_store();
    //     let token = SecretString::new(Uuid::new_v4().to_string().into_boxed_str());
    //     let result = map.store_token(&token.clone()).await;
    //     assert!(result.is_ok());
    //     let result = map.store_token(&token).await;
    //     assert!(result.is_err());
    // }

    #[tokio::test]
    async fn token_exist_true_test() {
        let mut map = create_store();
        let _ = map.store_token(&SecretString::new(String::from("12345").into_boxed_str())).await;

        let result = map.token_exists(&SecretString::new(String::from("12345").into_boxed_str())).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn token_exists_false_test() {
        let mut map = create_store();
        let _ = map.store_token(&SecretString::new(String::from("12345").into_boxed_str())).await;

        let result = map.token_exists(&SecretString::new(String::from("6789").into_boxed_str())).await.unwrap();
        assert!(!result);
    }
}