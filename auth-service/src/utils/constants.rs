use std::env;

use dotenvy::dotenv;
use lazy_static::lazy_static;
use secrecy::SecretString;

lazy_static! {
    pub static ref JWT_SECRET: SecretString = set_token();
    pub static ref DATABASE_URL: SecretString = set_db_url();
    pub static ref REDIS_HOST_NAME: String = set_redis_host();
    pub static ref POSTMARK_AUTH_TOKEN: SecretString = set_postmark_auth_token();
}

pub const JWT_COOKIE_NAME: &str = "jwt";
pub const DEFAULT_REDIS_HOSTNAME: &str = "127.0.0.1";

fn set_token() -> SecretString {
    dotenv().ok();
    let secret = env::var(myenv::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty");
    }
    SecretString::new(secret.into_boxed_str())
}
fn set_db_url() -> SecretString {
    dotenv().ok();
    let secret = env::var(myenv::DATABASE_URL_ENV_VAR).expect("DATABASE_URL must be set");
    if secret.is_empty() {
        panic!("DATABASE_URL must not be empty");
    }
    SecretString::new(secret.into_boxed_str())
}
fn set_redis_host() -> String {
    dotenv().ok();
    env::var(myenv::REDIS_HOST_NAME_ENV_VAR).unwrap_or(DEFAULT_REDIS_HOSTNAME.to_owned())
}
fn set_postmark_auth_token() -> SecretString {
    dotenv().ok();
    let secret = env::var(myenv::POSTMARK_AUTH_TOKEN_ENV_VAR).expect("POSTMARK_AUTH_TOKEN must be set");
    if secret.is_empty() {
        panic!("POSTMARK_AUTH_TOKEN must not be empty");
    }
    SecretString::new(secret.into_boxed_str())
}

pub mod myenv {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
    pub const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";
}

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
    pub mod email_client {
        use std::time::Duration;

        pub const BASE_URL: &str = "https:/api.postmarkapp.com/email";
        pub const SENDER: &str = "naginipython332@gmail.com";
        pub const TIMEOUT: Duration = Duration::from_secs(10);
    }
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
    pub mod email_client {
        use std::time::Duration;

        pub const SENDER: &str = "test@gmail.com";
        pub const TIMEOUT: Duration = Duration::from_millis(200);
    }
}