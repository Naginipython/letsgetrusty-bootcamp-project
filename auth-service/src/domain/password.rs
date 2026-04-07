
#[derive(Debug, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password, String> {
        if password.len() >= 8 {
            Ok(Password(password))
        } else {
            Err(String::from("Password is not valid"))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn string_should_become_an_password() {
        let password = Password::parse(String::from("password123"));

        assert!(password.is_ok());
    }
    #[test]
    fn invalid_password_should_fail() {
        let password = Password::parse(String::from("passwor"));

        assert!(password.is_err());
        assert_eq!(password, Err(String::from("Password is not valid")))
    }
    #[test]
    fn password_ref_should_be_viewed_as_a_str() {
        let password = Password::parse(String::from("password123")).unwrap();

        assert_eq!(password.as_ref(), "password123");
    }
}
