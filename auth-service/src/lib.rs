use std::error::Error;

use axum::{Json, Router, response::IntoResponse, routing::post, serve::Serve, http::{StatusCode, Method}};
use redis::{Client, RedisResult};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::ServeDir};

use crate::{app_state::AppState, domain::AuthAPIError, routes::*};

pub mod routes;
pub mod domain;
pub mod service;
pub mod app_state;
pub mod utils;

pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    pub address: String
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://157.230.85.215:8000".parse()?
        ];
        
        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);
        
        let assets_dir = ServeDir::new("assets");
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application {
            server,
            address
        })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing Token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid Token")
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string()
        });
        (status, body).into_response()
    }
}

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url).await
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}