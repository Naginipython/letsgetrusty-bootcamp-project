use std::hash::Hash;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}
impl Email {
    pub fn parse(email: SecretString) -> Result<Self> {
        if email.expose_secret().contains("@") {
            Ok(Email(email))
        } else {
            Err(eyre!("Email is not valid"))
        }
    }
}
impl Eq for Email {}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod email_tests {
    use super::*;

    #[test]
    fn string_should_become_an_email() {
        let email = Email::parse(SecretString::new(String::from("test@test.com").into_boxed_str()));

        assert!(email.is_ok());
    }
    #[test]
    fn invalid_email_should_fail() {
        let email = Email::parse(SecretString::new(String::from("testtest.com").into_boxed_str()));

        assert!(email.is_err());
    }
    #[test]
    fn email_ref_should_be_viewed_as_a_str() {
        let email = Email::parse(SecretString::new(String::from("test@test.com").into_boxed_str())).unwrap();

        assert_eq!(email.as_ref().expose_secret(), "test@test.com");
    }
}
