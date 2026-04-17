use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, HashedPassword, User}};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email);
    let password = HashedPassword::parse(request.password).await;

    if let (Ok(email), Ok(password)) = (email, password) {
        let user = User::new(email, password, request.requires_2fa);
        let mut user_store = state.user_store.write().await;

        if user_store.add_user(user).await.is_err() {
            return Err(AuthAPIError::UserAlreadyExists);
        }

        let response = Json(SignupResponse {
            message: String::from("User created successfully!")
        });

        Ok((StatusCode::CREATED, response))
    } else {
        Err(AuthAPIError::InvalidCredentials)
    }

}
