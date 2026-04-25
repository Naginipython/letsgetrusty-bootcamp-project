use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;

use crate::{app_state::AppState, domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode}, utils::auth::generate_auth_cookie};

#[derive(Deserialize)]
pub struct Verify2FARequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_fa_code: String,
}

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(request
): Json<Verify2FARequest>) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(SecretString::new(request.email.into_boxed_str())) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };
    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(id) => id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };
    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(code) => code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok(tuple) => tuple,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials))
    };
    if code_tuple != (login_attempt_id, two_fa_code) {
        return (jar, Err(AuthAPIError::IncorrectCredentials))
    }

    if let Err(e) = two_fa_code_store.remove_code(&email).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())))
    }

    let auth_cookie = generate_auth_cookie(&email);
    let updated_jar = match auth_cookie {
        Ok(cookie) => jar.add(cookie),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into())))
    };

    (updated_jar, Ok(StatusCode::OK.into_response()))
}
