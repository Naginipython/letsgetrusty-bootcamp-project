use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};

use crate::{app_state::AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    jar: CookieJar,
    State(state): State<AppState>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(c) => c,
        None => return (jar, Err(AuthAPIError::MissingToken))
    };

    let token = SecretString::new(cookie.value().to_owned().into_boxed_str());
    if let Err(_) = validate_token(&token.expose_secret(), state.banned_store.clone()).await {
        return (jar, Err(AuthAPIError::InvalidToken))
    }

    if let Err(e) = state.banned_store.write().await.store_token(&token).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())))
    }

    let jar = jar.remove(JWT_COOKIE_NAME);

    (jar, Ok(StatusCode::OK.into_response()))
}
