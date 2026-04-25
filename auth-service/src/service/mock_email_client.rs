use color_eyre::eyre::Result;
use secrecy::ExposeSecret;

use crate::domain::{EmailClient, Email};

#[derive(Default)]
pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        tracing::debug!("Sending email to {} with subject: {subject} and content: {content}", recipient.as_ref().expose_secret());
        
        Ok(())
    }
}