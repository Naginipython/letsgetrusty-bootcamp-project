use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    store: HashSet<String>
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        if self.store.contains(&String::from(token)) {
            return Err(BannedTokenStoreError::TokenExists)
        }
        self.store.insert(String::from(token));
        Ok(())
    }

    async fn token_exists(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.store.contains(&String::from(token)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn adding_to_store_doesnt_result_in_err() {
        let mut map = HashsetBannedTokenStore::default();
        let result = map.store_token("12345").await;
        assert!(result.is_ok())
    }

    #[tokio::test]
    async fn cant_add_token_if_already_exists() {
        let mut map = HashsetBannedTokenStore::default();
        let result = map.store_token("12345").await;
        assert!(result.is_ok());
        let result = map.store_token("12345").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn token_exist_true_test() {
        let mut map = HashsetBannedTokenStore::default();
        let _ = map.store_token("12345").await;

        let result = map.token_exists("12345").await;
        assert_eq!(Ok(true), result);
    }

    #[tokio::test]
    async fn token_exists_false_test() {
        let mut map = HashsetBannedTokenStore::default();
        let _ = map.store_token("12345").await;

        let result = map.token_exists("6789").await;
        assert_eq!(Ok(false), result);
    }
}
