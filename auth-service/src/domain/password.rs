use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};
use color_eyre::eyre::{Result, eyre};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "HashedPassword Parse", skip_all)]
    pub async fn parse(password: SecretString) -> Result<HashedPassword> {
        if password.expose_secret().len() < 8 {
            return Err(eyre!("Password is invalid"));
        }

        let result = compute_password_hash(&password).await?;
        Ok(Self(result))
    }

    #[tracing::instrument(name = "HashedPassword Parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.expose_secret().as_ref()) {
            Ok(Self(SecretString::new(hashed_string.to_string().into_boxed_str())))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(
        &self,
        password_candidate: &SecretString
    ) -> Result<()> {
        let current_span = tracing::Span::current();
        
        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        let task = tokio::task::spawn_blocking(move || {
            // makes sure the thread keep the context of the original span
            current_span.in_scope(|| {
                let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&password_hash)?;

                Argon2::default().verify_password(
                    password_candidate.as_bytes(),
                    &expected_password_hash).map_err(|e| e.into())
            })
        });

        task.await?
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span = tracing::Span::current();

    let password = password.expose_secret().to_owned();
    let task = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                argon2::Algorithm::Argon2i,
                argon2::Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?;

    task
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::from(String::from("").into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err())
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new(String::from("1234567").into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err())
    }

    // #[test]
    // fn can_parse_valid_argon2_hash() {
    //     let raw_password = "Password";
    //     let salt = SaltString::generate(&mut OsRng);
    //     let argon2 = Argon2::new(
    //         argon2::Algorithm::Argon2id,
    //         argon2::Version::V0x13,
    //         Params::new(15000, 2, 1, None).unwrap()
    //     );

    //     let hash_string = argon2
    //         .hash_password(raw_password.as_bytes(), &salt)
    //         .unwrap()
    //         .to_string();

    //     let hash_password = HashedPassword::parse_password_hash(
    //         SecretString::new(hash_string.into_boxed_str())
    //     ).unwrap();

    //     assert_eq!(hash_password.as_ref(), hash_string.as_str());
    //     assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"))
    // }

    // #[tokio::test]
    //     async fn can_verify_raw_password() {
    //         let raw_password = "TestPassword123";
    //         let salt = SaltString::generate(&mut OsRng);
    //         let argon2 = Argon2::new(
    //             argon2::Algorithm::Argon2id,
    //             argon2::Version::V0x13,
    //             Params::new(15000, 2, 1, None).unwrap(),
    //         );

    //         let hash_string = argon2
    //             .hash_password(raw_password.as_bytes(), &salt)
    //             .unwrap()
    //             .to_string();

    //         let hash_password = HashedPassword::parse_password_hash(
    //             hash_string
    //             .clone())
    //             .unwrap();

    //         assert_eq!(hash_password.as_ref(), hash_string.as_str());
    //         assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));

    //         let result = hash_password.verify_raw_password(raw_password).await;
    //         assert!(result.is_ok());
    //     }
}
