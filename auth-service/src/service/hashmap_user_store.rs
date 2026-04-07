use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

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

    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(email) {
            if user.password.as_ref() == password.as_ref() {
                Ok(())
            } else {
                Err(UserStoreError::InvalidCredentials)
            }
        } else {
            Err(UserStoreError::UserNotFound)
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), Password::parse(String::from("password")).unwrap(), false);
        let result = usermap.add_user(user).await;
        assert_eq!(result, Ok(()));

        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), Password::parse(String::from("password")).unwrap(), false);
        let result = usermap.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists))
    }

    #[tokio::test]
    async fn test_get_users() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), Password::parse(String::from("password")).unwrap(), false);
        let _ = usermap.add_user(user).await;

        let result = usermap.get_user(&Email::parse(String::from("test@test.com")).unwrap()).await;

        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), Password::parse(String::from("password")).unwrap(), false);
        assert_eq!(result, Ok(&user));
        let result = usermap.get_user(&Email::parse(String::from("bad_email@email.com")).unwrap()).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound))

    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(Email::parse(String::from("test@test.com")).unwrap(), Password::parse(String::from("password")).unwrap(), false);
        let _ = usermap.add_user(user).await;

        let result = usermap.validate_user(&Email::parse(String::from("test@test.com")).unwrap(), &Password::parse(String::from("password")).unwrap()).await;
        assert_eq!(result, Ok(()));

        let result = usermap.validate_user(&Email::parse(String::from("bad_email@email.com")).unwrap(), &Password::parse(String::from("password")).unwrap()).await;
        assert_eq!(result, Err(UserStoreError::UserNotFound));

        let result = usermap.validate_user(&Email::parse(String::from("test@test.com")).unwrap(), &Password::parse(String::from("badpassword")).unwrap()).await;
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));
    }
}
