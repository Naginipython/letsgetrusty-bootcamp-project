use auth_service::{ErrorResponse, routes::SignupResponse};
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn signup_returns_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    
    let test_cases = [
        json!({
            "email": random_email.clone(),
            "password": String::from("password123")
        }),
        json!({
            "password": String::from("password123"),
            "requires2FA": true
        }),
        json!({
            "email": random_email.clone(),
            "requires2FA": true
        })
    ];
    
    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        
        assert_eq!(response.status().as_u16(), 422, "Failed for input{}", test_case)
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    
    let test_case = json!({
        "email": String::from("test@test.com"),
        "password": String::from("password123"),
        "requires2FA": true,
    });
    
    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let expected_response = SignupResponse {
        message: String::from("User created successfully!")
    };
    
    assert_eq!(
        response.json::<SignupResponse>().await.expect("Could not deserialize body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let test_cases = [
        json!({
            "email": String::from("testtest.com"),
            "password": String::from("password123"),
            "requires2FA": true
        }),
        json!({
            "email": String::from("test@test.com"),
            "password": String::from("passwor"),
            "requires2FA": true
        })
    ];
    
    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", test_case);
        
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Could not deserialize response body to ErrorResponse").error,
            String::from("Invalid credentials")
        )
    }
}
    
#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let test_case = json!({
        "email": String::from("test@test.com"),
        "password": String::from("password123"),
        "requires2FA": true,
    });
    
    let _ = app.post_signup(&test_case).await;
    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 409);
    
    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Could not deserialize response body to ErrorResponse").error,
        String::from("User already exists")
    )
}