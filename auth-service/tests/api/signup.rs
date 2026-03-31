use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn signup_returns_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    
    let test_cases = [
        json!({
            "email": random_email.clone(),
            "password": "password123"
        }),
        json!({
            "password": "password123",
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