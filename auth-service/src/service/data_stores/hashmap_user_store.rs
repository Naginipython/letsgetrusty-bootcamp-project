use std::collections::HashMap;

use crate::domain::{Email, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {

    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound)
        }
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;
        
        user.password.verify_raw_password(raw_password).await.map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::HashedPassword;

    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), HashedPassword::parse(String::from("password")).await.unwrap(), false);
        let result = usermap.add_user(user.clone()).await;
        assert_eq!(result, Ok(()));

        let result = usermap.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists))
    }

    #[tokio::test]
    async fn test_get_users() {
        let mut usermap = HashmapUserStore::default();
        let password = HashedPassword::parse(String::from("password")).await.unwrap();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), password.clone(), false);
        let _ = usermap.add_user(user.clone()).await;

        let result = usermap.get_user(&Email::parse(String::from("test@test.com")).unwrap()).await;

        assert_eq!(result, Ok(user));
        let result = usermap.get_user(&Email::parse(String::from("bad_email@email.com")).unwrap()).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound))

    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut usermap = HashmapUserStore::default();
        let password = HashedPassword::parse(String::from("password")).await.unwrap();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), password, false);
        let _ = usermap.add_user(user).await;

        let result = usermap.validate_user(&Email::parse(String::from("test@test.com")).unwrap(), "password").await;
        assert_eq!(result, Ok(()));

        let result = usermap.validate_user(&Email::parse(String::from("bad_email@email.com")).unwrap(), "password").await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));

        let result = usermap.validate_user(&Email::parse(String::from("test@test.com")).unwrap(), "badpassword").await;
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));
    }
}
