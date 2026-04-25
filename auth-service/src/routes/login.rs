use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode}, utils::auth::generate_auth_cookie};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: SecretString,
    pub password: SecretString
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String
}

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };
    
    if request.password.expose_secret().len() < 8 {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }
    
    let user_store = &state.user_store.read().await;

    if let Err(_) = user_store.validate_user(&email, &request.password).await {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials))
    };

    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

#[tracing::instrument(name = "Handle no 2FA", skip_all)]
async fn handle_no_2fa(email: &Email, jar: CookieJar) -> (
    CookieJar, Result<(StatusCode, Json<LoginResponse>), AuthAPIError>
) {
    let auth_cookie = generate_auth_cookie(&email);
    let updated_jar = match auth_cookie {
        Ok(cookie) => jar.add(cookie),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e)))
    };

    (updated_jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}

#[tracing::instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa(email: &Email, state: &AppState, jar: CookieJar) -> (CookieJar, Result<(StatusCode, Json<LoginResponse>), AuthAPIError>) {
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    if let Err(e) = state.two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), code.clone())
        .await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())))
    }

    if let Err(e) = state
        .email_client
        .send_email(&email, "2FA Code", code.as_ref().expose_secret())
        .await {
        return (jar, Err(AuthAPIError::UnexpectedError(e)))
    }

    let result = TwoFactorAuthResponse {
        message: String::from("2FA required"),
        login_attempt_id: String::from(login_attempt_id.as_ref().expose_secret())
    };
    (jar, Ok((StatusCode::PARTIAL_CONTENT, Json(LoginResponse::TwoFactorAuth(result)))))
}
