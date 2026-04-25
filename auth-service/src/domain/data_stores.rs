use color_eyre::eyre::{eyre, Context, Report, Result};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use rand::Rng;
use uuid::Uuid;

use super::{User, Email};

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected Error")]
    UnexpectedError(#[source] Report)
}
#[derive(Debug, thiserror::Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report)
}
#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound) |
            (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists) |
            (Self::UserNotFound, Self::UserNotFound) |
            (Self::InvalidCredentials, Self::InvalidCredentials) |
            (Self::UnexpectedError(_), Self::UnexpectedError(_))
            
        )
    }
}

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, raw_password: &SecretString) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: &SecretString) -> Result<(), BannedTokenStoreError>;
    async fn token_exists(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(&mut self, email: Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let result = Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(LoginAttemptId(SecretString::new(result.to_string().into_boxed_str())))
    }
}
impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(SecretString::new(Uuid::new_v4().to_string().into_boxed_str()))
    }
}
impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct TwoFACode(SecretString);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;
        
        
        if (100_000..999_999).contains(&code_as_u32) {
            Ok(TwoFACode(SecretString::new(code.into_boxed_str())))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}
impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::rng().random_range(100_000..=999_999).to_string();
        TwoFACode(SecretString::new(code.into_boxed_str()))
    }
}
impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}