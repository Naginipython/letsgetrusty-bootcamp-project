use std::{str::FromStr, sync::Arc};

use auth_service::{Application, app_state::AppState, domain::{BannedTokenStore, Email, TwoFACodeStore}, get_postgres_pool, get_redis_client, service::{data_stores::{postgres_user_store::PostgresUserStore, redis_banned_token_store::RedisBannedTokenStore, redis_two_fa_code_store::RedisTwoFACodeStore}, mock_email_client::MockEmailClient, postmark_email_client::PostmarkEmailClient}, utils::constants::{DATABASE_URL, REDIS_HOST_NAME, test}};
use reqwest::{Client, cookie::Jar};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Connection, Executor, PgConnection, PgPool, postgres::{PgConnectOptions, PgPoolOptions}};
use tokio::sync::RwLock;
use uuid::Uuid;
use wiremock::MockServer;

#[macro_export]
macro_rules! app_test {
    (async fn $name:ident($app:ident) $body:block) => {
        #[tokio::test]
        async fn $name() {
            let mut $app = TestApp::new().await;
            $body
            $app.clean_up().await;
        }
    };
}

pub struct TestApp {
    pub address: String,
    pub db_name: String,
    pub did_drop_db: bool,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_store: Arc<RwLock<dyn BannedTokenStore + Send + Sync>>,
    pub two_fa_code_store: Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>,
    pub email_server: MockServer,
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let redis_conn = Arc::new(RwLock::new(configure_redis()));
        
        let email_server = MockServer::start().await;
        let base_url = email_server.uri();

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        // let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let banned_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn.clone())));
        // let banned_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_conn)));
        // let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(configure_postmark_email_client(base_url));
        // let email_client = Arc::new(MockEmailClient::default());
        let app_state = AppState::new(user_store, banned_store.clone(), two_fa_code_store.clone(), email_client);

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        TestApp {
            address,
            db_name,
            did_drop_db: false,
            cookie_jar,
            http_client,
            banned_store,
            two_fa_code_store,
            email_server
        }
    }

    pub async fn clean_up(&mut self) {
        delete_database(&self.db_name).await;
        self.did_drop_db = true;
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where Body: serde::Serialize {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute post signup request")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
   where Body: serde::Serialize {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute post login request")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute post logout request")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
   where Body: serde::Serialize {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute post verify-2fa request")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
   where Body: serde::Serialize {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute post verify-token request")
    }

    pub fn get_random_email() -> String {
        format!("{}@example.com", Uuid::new_v4())
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.did_drop_db {
            panic!("Forgot to drop DB!")
        }
    }
}

async fn configure_postgresql() -> (PgPool, String) {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgresql_conn_url.expose_secret(), &db_name).await;

    let postgresql_conn_url_with_db = SecretString::new(format!("{}/{}", postgresql_conn_url.expose_secret(), db_name).into_boxed_str());

    (get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create postgres connection pool"),
    db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create postgres connection pool");

    connection.execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");


    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    connection.execute(
        format!(r#"
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{}'
            AND pid <> pg_backend_pid();
            "#, db_name).as_str()
        )
        .await
        .expect("Failed to drop the database");

    connection
        .execute(format!("DROP DATABASE \"{}\";", db_name).as_str())
        .await
        .expect("Failed to drop the database");
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = SecretString::new(String::from("auth_token").into_boxed_str());
    
    let sender = Email::parse(SecretString::new(test::email_client::SENDER.to_owned().into_boxed_str())).unwrap();
    
    let http_client = Client::builder()
        .timeout(test::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");
    
    PostmarkEmailClient::new(http_client, base_url, sender, postmark_auth_token)
}