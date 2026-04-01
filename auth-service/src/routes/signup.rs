use axum::{Json, extract::State, response::IntoResponse};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::User};

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
) -> impl IntoResponse {
    let user = User::new(request.email, request.password, request.requires_2fa);
    
    let mut user_store = state.user_store.write().await;
    
    let _ = user_store.add_user(user).unwrap(); // TODO: error handle
    
    let response = Json(SignupResponse {
        message: String::from("User created successfully!")
    });
    
    (StatusCode::CREATED, response)
}