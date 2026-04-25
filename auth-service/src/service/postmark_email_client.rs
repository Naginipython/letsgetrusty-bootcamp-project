use color_eyre::eyre::Result;
use reqwest::{Client, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::domain::{Email, EmailClient};

const MESSAGE_STREAM: &str = "outbound";
const POSTMARK_AUTH_HEADER: &str = "X-Postmark-Server-Token";

pub struct PostmarkEmailClient {
    http_client: Client,
    base_url: String,
    sender: Email,
    auth_token: SecretString
}

impl PostmarkEmailClient {
    pub fn new(http_client: Client, base_url: String, sender: Email, auth_token: SecretString) -> Self {
        Self {
            http_client,
            base_url,
            sender,
            auth_token
        }
    }
}

#[async_trait::async_trait]
impl EmailClient for PostmarkEmailClient {
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        let base = Url::parse(&self.base_url)?;
        let url = base.join("/email")?;

        let request_body = SendEmailRequest {
            from: self.sender.as_ref().expose_secret(),
            to: recipient.as_ref().expose_secret(),
            subject,
            html_body: content,
            text_body: content,
            message_stream: MESSAGE_STREAM
        };

        let request = self
            .http_client
            .post(url)
            .header(
                POSTMARK_AUTH_HEADER,
                self.auth_token.expose_secret()
            )
            .json(&request_body);

        request.send().await?.error_for_status()?;

        Ok(())
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct SendEmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    html_body: &'a str,
    text_body: &'a str,
    message_stream: &'a str,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fake::{Fake, Faker, faker::{internet::zh_tw::SafeEmail, lorem::en::Sentence}};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{any, header, header_exists, method, path}};

    use crate::utils::constants::test;

    use super::*;

    fn subject() -> String {
        Sentence(1..2).fake()
    }
    fn content() -> String {
        Sentence(1..10).fake()
    }
    fn email() -> Email {
        Email::parse(SecretString::new(SafeEmail().fake::<String>().into_boxed_str())).unwrap()
    }
    fn email_client(base_url: String) -> PostmarkEmailClient {
        let http_client = Client::builder()
            .timeout(test::email_client::TIMEOUT)
            .build()
            .unwrap();
        PostmarkEmailClient::new(
            http_client,
            base_url,
            email(),
            SecretString::new(Faker.fake::<String>().into_boxed_str()),
        )
    }

    struct SendEmailBodyMatcher;

    impl wiremock::Match for SendEmailBodyMatcher {
        fn matches(&self, request: &wiremock::Request) -> bool {
            let result: Result<serde_json::Value, _> = serde_json::from_slice(&request.body);
            if let Ok(body) = result {
                body.get("From").is_some() &&
                body.get("To").is_some() &&
                body.get("Subject").is_some() &&
                body.get("HtmlBody").is_some() &&
                body.get("MessageStream").is_some()
            } else {
                false
            }
        }
    }

    #[tokio::test]
    async fn send_email_sends_the_expected_request() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        Mock::given(header_exists(POSTMARK_AUTH_HEADER))
            .and(header("Content-Type", "application/json"))
            .and(path("/email"))
            .and(method("POST"))
            .and(SendEmailBodyMatcher)
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client.send_email(
            &email(),
            &subject(),
            &content()
        ).await;

        assert!(outcome.is_ok())
    }

    #[tokio::test]
    async fn send_email_fails_if_the_server_return_500() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client.send_email(
            &email(),
            &subject(),
            &content()
        ).await;

        assert!(outcome.is_err())
    }

    #[tokio::test]
    async fn send_email_times_out_if_the_server_takes_too_long() {
        let mock_server = MockServer::start().await;
        let email_client = email_client(mock_server.uri());

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(180)))
            .expect(1)
            .mount(&mock_server)
            .await;

        let outcome = email_client.send_email(
            &email(), &subject(), &content()
        ).await;

        assert!(outcome.is_err())
    }
}
