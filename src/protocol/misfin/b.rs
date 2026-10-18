use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::{
    error::RequestError,
    mailbox::{Identity, Message},
    protocol::AsMessage,
    tls::Cert,
};
use std::{path::PathBuf, str::FromStr, time::SystemTime};

#[derive(Debug)]
pub struct Request {
    pub mailbox: String,
    pub hostname: String,
    pub message: String,
}

impl FromStr for Request {
    type Err = RequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mailbox, remainder) = s
            .strip_prefix("misfin://")
            .and_then(|s| s.split_once('@'))
            .ok_or(RequestError::InvalidRequest)?;

        let (hostname, message) = remainder
            .split_once(' ')
            .ok_or(RequestError::InvalidRequest)?;

        let mut message = message.to_string();
        message.push('\n');

        Ok(Request {
            mailbox: mailbox.to_string(),
            hostname: hostname.to_string(),
            message,
        })
    }
}

impl AsMessage for Request {
    type Err = RequestError;

    async fn as_message(
        &self,
        cert: Option<CertificateDer<'_>>,
        trust: PathBuf,
    ) -> Result<crate::mailbox::Message, Self::Err> {
        let mut message = Message {
            timestamp: Some(SystemTime::now().into()),
            sender: Identity::default(),
            recipient: Identity {
                mailbox: self.mailbox.clone(),
                hostname: self.hostname.clone(),
            },
            message: self.message.clone(),
        };

        if !self.message.trim().is_empty() {
            if let Some(inner) = cert {
                let sender = Cert::verify(&inner, trust).await?;
                message.sender = sender;

                // Write metadata lines to message
                let mut meta = format!(
                    "{}\n{}\n{}\n",
                    message.sender,
                    message.recipient,
                    message.timestamp.unwrap().to_rfc3339()
                );
                meta.push_str(&message.message);
                message.message = meta;
            } else {
                return Err(RequestError::CertificateRequired);
            }
        }

        Ok(message)
    }
}
