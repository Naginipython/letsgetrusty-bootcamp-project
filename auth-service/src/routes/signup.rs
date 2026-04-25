use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, HashedPassword, User}};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: SecretString,
    pub password: SecretString,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String
}

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    
    let password = HashedPassword::parse(request.password)
        .await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);
    let mut user_store = state.user_store.write().await;

    user_store.add_user(user).await.map_err(|_| AuthAPIError::UserAlreadyExists)?;

    let response = Json(SignupResponse {
        message: String::from("User created successfully!")
    });

    Ok((StatusCode::CREATED, response))

}
