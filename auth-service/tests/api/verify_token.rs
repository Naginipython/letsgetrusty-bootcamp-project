use auth_service::{ErrorResponse, utils::constants::JWT_COOKIE_NAME};
use serde_json::json;

use crate::{app_test, helpers::TestApp};

app_test! {
    async fn should_return_422_if_malformed_input(app) {
        let body = json!({});
        let response = app.post_verify_token(&body).await;
        assert_eq!(response.status().as_u16(), 422);
    }
}

app_test! {
    async fn should_return_200_valid_token(app) {
        let email = TestApp::get_random_email();
        let body = json!({
            "email": &email,
            "password": "password",
            "requires2FA": false
        });
        let response = app.post_signup(&body).await;
        assert_eq!(response.status().as_u16(), 201);

        let body2 = json!({
            "email": &email,
            "password": "password"
        });
        let response = app.post_login(&body2).await;
        assert_eq!(response.status().as_u16(), 200);

        let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
        assert!(!auth_cookie.value().is_empty());

        let body3 = json!({
            "token": auth_cookie.value()
        });
        let response = app.post_verify_token(&body3).await;
        assert_eq!(response.status().as_u16(), 200);
    }
}

app_test! {
    async fn should_return_401_if_invalid_token(app) {
        let body = json!({
            "token": "invalid_token"
        });
        let response = app.post_verify_token(&body).await;
        assert_eq!(response.status().as_u16(), 401);
        assert_eq!(
            response.json::<ErrorResponse>().await.expect("Error parsing Error response").error,
            String::from("Invalid Token")
        );
    }
}

app_test! {
    async fn should_return_401_if_banned_token(app) {
        let email = TestApp::get_random_email();
        let body = json!({
            "email": &email,
            "password": "password",
            "requires2FA": false
        });
        let response = app.post_signup(&body).await;
        assert_eq!(response.status().as_u16(), 201);

        let body2 = json!({
            "email": &email,
            "password": "password"
        });
        let response = app.post_login(&body2).await;
        assert_eq!(response.status().as_u16(), 200);

        let auth_cookie = response
            .cookies()
            .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
            .expect("No auth cookie found");
        assert!(!auth_cookie.value().is_empty());

        let response = app.post_logout().await;
        assert_eq!(response.status().as_u16(), 200);

        let body3 = json!({
            "token": auth_cookie.value()
        });
        let response = app.post_verify_token(&body3).await;
        assert_eq!(response.status().as_u16(), 401);
    }
}
