use auth_service::{ErrorResponse, domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore}, utils::constants::JWT_COOKIE_NAME};
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_bodies = [
        json!({
            "email": "test@test.com",
            "loginAttemptId": "123456",
        }),
        json!({
            "email": "test@test.com",
            "2FACode": "123456"
        }),
        json!({
            "loginAttemptId": "123456",
            "2FACode": "123456"
        }),
    ];

    for test in test_bodies {
        let response = app.post_verify_2fa(&test).await;
        assert_eq!(response.status().as_u16(), 422);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let two_fa_code = TwoFACode::default();
    let attempt_id = LoginAttemptId::default();

    let test_bodies = [
        json!({
            "email": "testtest.com",
            "loginAttemptId": attempt_id.as_ref(),
            "2FACode": two_fa_code.as_ref()
        }),
        json!({
            "email": "test@test.com",
            "loginAttemptId": "1234",
            "2FACode": two_fa_code.as_ref()
        }),
        json!({
            "email": "test@test.com",
            "loginAttemptId": attempt_id.as_ref(),
            "2FACode": "123"
        })
    ];

    for test in test_bodies {
        let response = app.post_verify_2fa(&test).await;
        assert_eq!(response.status().as_u16(), 400);
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Could not parse ErrorResponse").error,
            String::from("Invalid credentials")
        )
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    // no email in store
    let email_test = json!({
        "email": "test@test.com",
        "loginAttemptId": LoginAttemptId::default().as_ref(),
        "2FACode": TwoFACode::default().as_ref()
    });
    
    let response = app.post_verify_2fa(&email_test).await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Could not parse ErrorResponse").error,
        String::from("Incorrect credentials")
    );
    
    // incorrect login_attempt_id & 2FACode
    let signup = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&login).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let (login_attempt_id, two_fa_code) = app.two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(String::from("test@test.com")).unwrap())
        .await
        .unwrap();
    let verify_two_fa_tests = [
        json!({
            "email": "test@test.com",
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "2FACode": two_fa_code.as_ref()
        }),
        json!({
            "email": "test@test.com",
            "loginAttemptId": login_attempt_id.as_ref(),
            "2FACode": TwoFACode::default().as_ref()
        }),
    ];
    for test_body in verify_two_fa_tests.iter() {
        let response = app.post_verify_2fa(test_body).await;
        assert_eq!(response.status().as_u16(), 401);
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Could not parse ErrorResponse").error,
            String::from("Incorrect credentials")
        );
    }
    
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
    
    let signup = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&login).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let (_, first_two_fa_code) = app.two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(String::from("test@test.com")).unwrap())
        .await
        .unwrap();
    
    let login = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&login).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let (second_login_attempt_id, _) = app.two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(String::from("test@test.com")).unwrap())
        .await
        .unwrap();
    
    let verify_two_fa = json!({
        "email": "test@test.com",
        "loginAttemptId": second_login_attempt_id.as_ref(),
        "2FACode": first_two_fa_code.as_ref()
    });
    
    let response = app.post_verify_2fa(&verify_two_fa).await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response.json::<ErrorResponse>().await.expect("Could not parse ErrorResponse").error,
        String::from("Incorrect credentials")
    );
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    
    let signup = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&login).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let (login_attempt_id, two_fa_code) = app.two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(String::from("test@test.com")).unwrap())
        .await
        .unwrap();
    let verify_two_fa = json!({
        "email": "test@test.com",
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": two_fa_code.as_ref()
    });
    
    let response = app.post_verify_2fa(&verify_two_fa).await;
    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    
    let signup = json!({
        "email": "test@test.com",
        "password": "password",
        "requires2FA": true
    });
    let response = app.post_signup(&signup).await;
    assert_eq!(response.status().as_u16(), 201);
    
    let login = json!({
        "email": "test@test.com",
        "password": "password"
    });
    let response = app.post_login(&login).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let (login_attempt_id, two_fa_code) = app.two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(String::from("test@test.com")).unwrap())
        .await
        .unwrap();
    let verify_two_fa = json!({
        "email": "test@test.com",
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": two_fa_code.as_ref()
    });
    
    let response = app.post_verify_2fa(&verify_two_fa).await;
    assert_eq!(response.status().as_u16(), 200);
    
    let response = app.post_verify_2fa(&verify_two_fa).await;
    assert_eq!(response.status().as_u16(), 401);
}