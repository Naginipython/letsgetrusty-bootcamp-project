use std::env;

use dotenvy::dotenv;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
}

pub const JWT_COOKIE_NAME: &str = "jwt";

fn set_token() -> String {
    dotenv().ok();
    let secret = env::var(myenv::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty");
    }
    secret
}

pub mod myenv {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
}
