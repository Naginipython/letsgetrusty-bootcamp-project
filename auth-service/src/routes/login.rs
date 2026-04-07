use axum::{Json, extract::State, response::IntoResponse, http::StatusCode};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password}, utils::auth::generate_auth_cookie};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginResponse {
    pub error: String
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    if let (Ok(email), Ok(password)) = (Email::parse(request.email), Password::parse(request.password)) {
        let user_store = &state.user_store.read().await;

        if let Err(_) = user_store.validate_user(&email, &password).await {
            return (jar, Err(AuthAPIError::IncorrectCredentials));
        }

        if let Err(_) = user_store.get_user(&email).await {
            return (jar, Err(AuthAPIError::IncorrectCredentials))
        }
        
        let auth_cookie = generate_auth_cookie(&email);
        let updated_jar = match auth_cookie {
            Ok(cookie) => jar.add(cookie),
            Err(_) => return (jar, Err(AuthAPIError::UnexpectedError))
        };

        (updated_jar, Ok(StatusCode::OK.into_response()))
    } else {
        (jar, Err(AuthAPIError::InvalidCredentials))
    }
}
