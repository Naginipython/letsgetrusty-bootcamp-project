use std::sync::Arc;

use redis::{Connection, TypedCommands};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code";

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(&mut self, email: Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa = TwoFATuple(String::from(login_attempt_id.as_ref()), String::from(code.as_ref()));
        match serde_json::to_string(&two_fa) {
            Err(_) => return Err(TwoFACodeStoreError::UnexpectedError),
            Ok(value) => {
                if let Err(_) = self.conn.write().await.set_ex(key, value, TEN_MINUTES_IN_SECONDS) {
                    return Err(TwoFACodeStoreError::UnexpectedError)
                }
                Ok(())
            }
        }
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        
        self.conn.write().await.del(key).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        
        Ok(())
    }
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(&email);
        let data = self.conn
            .write()
            .await
            .get(key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?
            .ok_or(TwoFACodeStoreError::UnexpectedError)?;
        
        let tuple: TwoFATuple = serde_json::from_str(&data).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        if let (Ok(login_attempt_id), Ok(two_fa_code)) = (LoginAttemptId::parse(tuple.0), TwoFACode::parse(tuple.1)) {
            Ok((login_attempt_id, two_fa_code))
        } else {
            Err(TwoFACodeStoreError::UnexpectedError)
        }
    }
}

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{get_redis_client, utils::constants::REDIS_HOST_NAME};

    use super::*;
    
    fn get_map() -> RedisTwoFACodeStore {
        let config = get_redis_client(REDIS_HOST_NAME.to_owned())
            .expect("Failed to get Redis client")
            .get_connection()
            .expect("Failed to get Redis connection");
        RedisTwoFACodeStore { conn: Arc::new(RwLock::new(config)) }
    }
    fn get_random_email() -> String {
        format!("{}@example.com", Uuid::new_v4())
    }
    
    #[tokio::test]
    async fn add_code_works() {
        let email = Email::parse(get_random_email()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        
        let mut map = get_map();
        let result = map.add_code(email, login_attempt_id, code).await;
        assert!(result.is_ok())
    }
    #[tokio::test]
    async fn remove_code_removes_valid_id() {
        let email = Email::parse(get_random_email()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        
        let mut map = get_map();
        let result = map.add_code(email.clone(), login_attempt_id, code).await;
        assert!(result.is_ok());
        
        let result = map.remove_code(&email).await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn get_code_works_for_valid_entry() {
        let email = Email::parse(get_random_email()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        
        let mut map = get_map();
        let result = map.add_code(
            email.clone(),
            login_attempt_id.clone(),
            code.clone()
        ).await;
        assert!(result.is_ok());
        
        let result = map.get_code(&email).await.unwrap();
        assert_eq!(result.0, login_attempt_id);
        assert_eq!(result.1, code);
    }
    #[tokio::test]
    async fn get_code_fails_for_invalid_code() {
        let map = get_map();
        
        let email = Email::parse(get_random_email()).unwrap();
        let result = map.get_code(&email).await;
        assert!(result.is_err());
    }
}