use std::collections::HashMap;

use crate::domain::User;


#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError
}

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }
    pub fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        if let Some(user) = self.users.get(email) {
            if user.password == password {
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

    #[test]
    fn test_add_user() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(String::from("test@test.com"), String::from("password"), false);
        let result = usermap.add_user(user);
        assert_eq!(result, Ok(()));

        let user = User::new(String::from("test@test.com"), String::from("password"), false);
        let result = usermap.add_user(user);
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists))
    }

    #[test]
    fn test_get_users() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(String::from("test@test.com"), String::from("password"), false);
        let _ = usermap.add_user(user);

        let result = usermap.get_user("test@test.com");

        let user = User::new(String::from("test@test.com"), String::from("password"), false);
        assert_eq!(result, Ok(&user));

        let result = usermap.get_user("bad_email@email.com");
        assert_eq!(result, Err(UserStoreError::UserNotFound))
    }

    #[test]
    fn test_validate_user() {
        let mut usermap = HashmapUserStore::default();
        let user = User::new(String::from("test@test.com"), String::from("password"), false);
        let _ = usermap.add_user(user);

        let result = usermap.validate_user("test@test.com", "password");
        assert_eq!(result, Ok(()));

        let result = usermap.validate_user("bad_email@email.com", "password");
        assert_eq!(result, Err(UserStoreError::UserNotFound));

        let result = usermap.validate_user("test@test.com", "badpassword");
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));
    }
}
