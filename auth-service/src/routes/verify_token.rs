use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

pub async fn verify_token(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(token): Json<VerifyTokenRequest>
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    if let Err(_) = validate_token(&token.token, state.banned_store.clone()).await {
        return (jar, Err(AuthAPIError::InvalidToken))
    }
    
    (jar, Ok(StatusCode::OK.into_response()))
}
