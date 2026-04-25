use axum_extra::extract::cookie::Cookie;
use chrono::Utc;
use color_eyre::eyre::{Context, ContextCompat, Result, eyre};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, encode, decode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{app_state::BannedTokenStoreType, domain::Email, utils::constants::{JWT_COOKIE_NAME, JWT_SECRET}};

pub const TOKEN_TTL_SECONDS: i64 = 600;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize
}

#[tracing::instrument(name = "Generate auth cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

#[tracing::instrument(name = "Validate token", skip_all)]
pub async fn validate_token(token: &str, banned_store: BannedTokenStoreType) -> Result<Claims> {
    match banned_store.read().await.token_exists(&SecretString::new(String::from(token).into_boxed_str())).await {
        Ok(value) => {
            if value {
                return Err(eyre!("token is banned"));
            }
        }
        Err(e) => return Err(e.into())
    }


    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default()
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

#[tracing::instrument(name = "Create auth cookie", skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(axum_extra::extract::cookie::SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations
        .build();

    cookie
}

#[tracing::instrument(name = "Generate auth token", skip_all)]
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!("failed to cast exp time to usize. exp time: {exp}"))?;

    let sub = email.as_ref().expose_secret().to_owned();
    let claims = Claims { sub, exp };

    create_token(&claims)
}

#[tracing::instrument(name = "Create token", skip_all)]
fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[cfg(test)]
mod auth_tests {
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(SecretString::new(String::from("test@test.com").into_boxed_str())).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(axum_extra::extract::cookie::SameSite::Lax))
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = String::from("test_token");
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(axum_extra::extract::cookie::SameSite::Lax))
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(SecretString::new(String::from("test@test.com").into_boxed_str())).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    // #[tokio::test]
    // async fn test_validate_token_with_valid_token() {
    //     let email = Email::parse(String::from("test@test.com")).unwrap();
    //     let token = generate_auth_token(&email).unwrap();
    //     let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));

    //     let result = validate_token(&token, banned_store).await.unwrap();
    //     assert_eq!(result.sub, "test@test.com");

    //     let exp = Utc::now()
    //         .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
    //         .expect("valid timestamp")
    //         .timestamp();

    //     assert!(result.exp > exp as usize);
    // }

    // #[tokio::test]
    // async fn test_validate_token_with_invalid_token() {
    //     let token = String::from("invalid token");
    //     let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));

    //     let result = validate_token(&token, banned_store).await;
    //     assert!(result.is_err());
    // }

    // #[tokio::test]
    // async fn test_validate_token_with_banned_token() {
    //     let email = Email::parse(String::from("test@test.com")).unwrap();
    //     let token = generate_auth_token(&email).unwrap();
    //     let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));

    //     let _ = banned_store.write().await.store_token(&token).await;

    //     let result = validate_token(&token, banned_store).await;
    //     assert!(result.is_err());
    // }
}
