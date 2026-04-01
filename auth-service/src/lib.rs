use std::error::Error;

use axum::{Router, routing::post, serve::Serve};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

use crate::{app_state::AppState, routes::*};

pub mod routes;
pub mod domain;
pub mod service;
pub mod app_state;

pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    pub address: String
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ServeDir::new("assets");
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .with_state(app_state);

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
