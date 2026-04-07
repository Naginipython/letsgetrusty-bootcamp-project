use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": "test@test.com",
        }),
        json!({
            "password": "password",
        })
    ];

    for test_case in test_cases.iter() {
        let result = app.post_login(test_case).await;
        assert_eq!(result.status().as_u16(), 422);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    
    let test_cases = [
        json!({
            "email": "bademail.com",
            "password": "password"
        }),
        json!({
            "email": "test@test.com",
            "password": "passwor"
        })
    ];
    
    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(response.status().as_u16(), 400);
        
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
            String::from("Invalid credentials")
        );
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    
    let signup_body = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": false
    });
    let _ = app.post_signup(&signup_body).await;
    
    let test_case = json!({
        "email": "test@test.com",
        "password": "wrongpassword"
    });
    let response = app.post_login(&test_case).await;
    assert_eq!(response.status().as_u16(), 401);
    
    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
        String::from("Incorrect credentials")
    )
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;
    
    let body = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": false
    });
    let response = app.post_signup(&body).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let body2 = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&body2).await;
    assert_eq!(response.status().as_u16(), 200);
    
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty())
}