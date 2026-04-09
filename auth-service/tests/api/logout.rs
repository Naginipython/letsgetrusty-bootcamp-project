use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use reqwest::Url;
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
        String::from("Missing Token")
    )
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!("{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/", JWT_COOKIE_NAME),
        &Url::parse("http://127.0.0.1").expect("Failed to parse UTL")
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
        String::from("Invalid Token")
    )
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    
    let signup_body = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login_body = json!({
        "email": "test@test.com",
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
    
    let auth_cookie = response.cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;
    
    let signup_body = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login_body = json!({
        "email": "test@test.com",
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