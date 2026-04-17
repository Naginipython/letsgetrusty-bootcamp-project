use std::error::Error;

use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};

#[derive(Debug, PartialEq, Clone)]
pub struct HashedPassword(String);

impl HashedPassword {
    pub async fn parse(password: String) -> Result<HashedPassword, String> {
        if password.len() < 8 {
            return Err(String::from("Password is invalid"));
        }
        
        match compute_password_hash(&password).await {
            Ok(hashed_password) => Ok(Self(hashed_password)),
            Err(_) => Err(String::from("Failed to hash password"))
        }
    }
    
    pub fn parse_password_hash(hash: String) -> Result<HashedPassword, String> {
        match PasswordHash::new(&hash) {
            Ok(hashed_string) => Ok(Self(hashed_string.to_string())),
            Err(_) => Err(String::from("Failed to parse string to a hashed password"))
        }
    }
    
    pub async fn verify_raw_password(
        &self, 
        password_candidate: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();
        
        
        let task = tokio::task::spawn_blocking(move || {
            let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&password_hash)?;
            
            Argon2::default().verify_password(
                  password_candidate.as_bytes(),
                  &expected_password_hash).map_err(|e| e.into())
        });
        
        task.await?
    }
}

async fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let password = password.to_owned();
    
    let task = tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::new(
            argon2::Algorithm::Argon2i, 
            argon2::Version::V0x13, 
            Params::new(15000, 2, 1, None)?,
        )
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
        
        Ok(password_hash)
    })
    .await?;
    
    task
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = String::from("");
        assert!(HashedPassword::parse(password).await.is_err())
    }
    
    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = String::from("1234567");
        assert!(HashedPassword::parse(password).await.is_err())
    }
    
    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "Password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap()
        );
        
        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        
        let hash_password = HashedPassword::parse_password_hash(
            hash_string.clone()
        ).unwrap();
        
        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"))
    }
    
    #[tokio::test]
        async fn can_verify_raw_password() {
            let raw_password = "TestPassword123";
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                Params::new(15000, 2, 1, None).unwrap(),
            );
    
            let hash_string = argon2
                .hash_password(raw_password.as_bytes(), &salt)
                .unwrap()
                .to_string();
    
            let hash_password = HashedPassword::parse_password_hash(
                hash_string
                .clone())
                .unwrap();
    
            assert_eq!(hash_password.as_ref(), hash_string.as_str());
            assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
    
            let result = hash_password.verify_raw_password(raw_password).await;
            assert!(result.is_ok());
        }
}
