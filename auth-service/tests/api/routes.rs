use crate::{app_test, helpers::TestApp};

app_test! {
    async fn root_returns_auth_ui(app) {
        let response = app.get_root().await;
    
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
    }
}
