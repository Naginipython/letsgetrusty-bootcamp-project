use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use reqwest::Url;
use secrecy::SecretString;
use serde_json::json;

use crate::{app_test, helpers::TestApp};

app_test! {
    async fn should_return_400_if_jwt_cookie_missing(app) {
        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 400);
    
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
            String::from("Missing Token")
        );
    }
}

app_test! {
    async fn should_return_401_if_invalid_token(app) {
        app.cookie_jar.add_cookie_str(
            &format!("{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/", JWT_COOKIE_NAME),
            &Url::parse("http://127.0.0.1").expect("Failed to parse UTL")
        );
    
        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 401);
    
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
            String::from("Invalid Token")
        );
    }
}

app_test! {
    async fn should_return_200_if_valid_jwt_cookie(app) {
        let email = TestApp::get_random_email();
        let signup_body = json!({
            "email": &email,
            "password": "password",
            "requires2FA": false
        });
        let response = app.post_signup(&signup_body).await;
        assert_eq!(response.status().as_u16(), 201);
    
        let login_body = json!({
            "email": &email,
            "password": "password"
        });
        let response = app.post_login(&login_body).await;
        assert_eq!(response.status().as_u16(), 200);
    
        let auth_cookie = response.cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
        assert!(!auth_cookie.value().is_empty());
    
        let token = SecretString::new(String::from(auth_cookie.value()).into_boxed_str());
    
        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 200);
    
        let auth_cookie = response.cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
        assert!(auth_cookie.value().is_empty());
    
        let result = app.banned_store.read().await.token_exists(&token).await.unwrap();
        assert!(result);
    }
}

app_test! {
    async fn should_return_400_if_logout_called_twice_in_a_row(app) {
        let email = TestApp::get_random_email();
        let signup_body = json!({
            "email": &email,
            "password": "password",
            "requires2FA": false
        });
        let response = app.post_signup(&signup_body).await;
        assert_eq!(response.status().as_u16(), 201);
    
        let login_body = json!({
            "email": &email,
            "password": "password"
        });
        let response = app.post_login(&login_body).await;
        assert_eq!(response.status().as_u16(), 200);
    
        let auth_cookie = response.cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
        assert!(!auth_cookie.value().is_empty());
    
        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 200);
    
        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 400);
    }
}
