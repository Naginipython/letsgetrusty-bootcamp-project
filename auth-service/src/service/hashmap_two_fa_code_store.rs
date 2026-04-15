use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Debug, PartialEq, Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(&mut self, email: Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound)
        }
    }
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(result) => Ok(result.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn add_code_works() {
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(String::from("123456")).unwrap();
        
        let mut map = HashmapTwoFACodeStore::default();
        let result = map.add_code(email, login_attempt_id, code).await;
        assert!(result.is_ok())
    }
    
    #[tokio::test]
    async fn remove_code_removes_valid_id() {
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(String::from("123456")).unwrap();
        
        let mut map = HashmapTwoFACodeStore::default();
        let result = map.add_code(email, login_attempt_id, code).await;
        assert!(result.is_ok());
        
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let result = map.remove_code(&email).await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn remove_code_throws_error_with_invalid_id() {
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(String::from("123456")).unwrap();
        
        let mut map = HashmapTwoFACodeStore::default();
        let result = map.add_code(email, login_attempt_id, code).await;
        assert!(result.is_ok());
        
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let result = map.remove_code(&email).await;
        assert!(result.is_ok());
        
        let result = map.remove_code(&email).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn remove_code_throws_error_with_no_id() {
        let mut map = HashmapTwoFACodeStore::default();
        
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let result = map.remove_code(&email).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn get_code_works_for_valid_entry() {
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(String::from("123456")).unwrap();
        
        let mut map = HashmapTwoFACodeStore::default();
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
        let map = HashmapTwoFACodeStore::default();
        
        let email = Email::parse(String::from("test@test.com")).unwrap();
        let result = map.get_code(&email).await;
        assert!(result.is_err());
    }
}