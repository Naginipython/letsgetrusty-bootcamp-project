use sqlx::PgPool;

use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};

pub struct PostgresUserStore {
    pool: PgPool
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let result = sqlx::query!(
            "SELECT email FROM users WHERE email = $1",
            user.email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;
        
        if result.is_some() {
            return Err(UserStoreError::UserAlreadyExists)
        }
        
        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            user.password.as_ref(),
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;
        
        Ok(())
    }
    
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let row = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1", 
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::UserNotFound)?;
        
        let user = User {
            email: Email::parse(row.email).map_err(|_| UserStoreError::UnexpectedError)?,
            password: HashedPassword::parse_password_hash(row.password_hash).map_err(|_| UserStoreError::UnexpectedError)?,
            requires_2fa: row.requires_2fa,
        };
        
        Ok(user)
    }
    
    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        
        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}