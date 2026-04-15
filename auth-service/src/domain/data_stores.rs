use rand::Rng;
use uuid::Uuid;

use super::{User, Password, Email};

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError
}
#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    TokenExists,
    UnexpectedError
}
#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError
}

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError>;
    async fn token_exists(&self, token: &str) -> bool;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(&mut self, email: Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        let result = Uuid::parse_str(&id);
        match result {
            Ok(uuid) => Ok(LoginAttemptId(uuid.to_string())),
            Err(e) => Err(format!("{}", e.to_string())),
        }
    }
}
impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}
impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        if let Err(_) = code.parse::<u32>() {
            return Err(String::from("Code is not a valid positive number"))
        }
        
        if code.len() == 6 {
            Ok(TwoFACode(code))
        } else {
            Err(String::from("Number is not 6 characters"))
        }
    }
}
impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::rng().random_range(100_000..=999_999).to_string();
        TwoFACode(code)
    }
}
impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}