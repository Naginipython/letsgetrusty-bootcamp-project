
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if email.contains("@") {
            Ok(Email(email))
        } else {
            Err(String::from("Email is not valid"))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod email_tests {
    use super::*;

    #[test]
    fn string_should_become_an_email() {
        let email = Email::parse(String::from("test@test.com"));

        assert!(email.is_ok());
    }
    #[test]
    fn invalid_email_should_fail() {
        let email = Email::parse(String::from("testtest.com"));

        assert!(email.is_err());
        assert_eq!(email, Err(String::from("Email is not valid")))
    }
    #[test]
    fn email_ref_should_be_viewed_as_a_str() {
        let email = Email::parse(String::from("test@test.com")).unwrap();

        assert_eq!(email.as_ref(), "test@test.com");
    }
}
