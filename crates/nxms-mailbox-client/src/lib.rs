use anyhow::{Context, Result, anyhow};
use nxms_transport::wire::NxmsEnvelope;
use reqwest::{Client, Proxy, StatusCode, Url};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct MailboxClient {
    base: Url,
    http: Client,
    push_token: Option<String>,
    pull_token: Option<String>,
    ack_token: Option<String>,
    admin_token: Option<String>,
}

impl MailboxClient {
    pub fn builder(base_url: &str) -> Result<MailboxClientBuilder> {
        Ok(MailboxClientBuilder::new(base_url)?)
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    pub async fn health(&self) -> Result<()> {
        let url = self.base.join("/health")?;
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(http_error(resp.status(), resp.text().await.ok()));
        }
        Ok(())
    }

    pub async fn push(
        &self,
        envelope: &NxmsEnvelope,
        ttl_secs: Option<u64>,
    ) -> Result<PushResponse> {
        let url = self.base.join("/v1/push")?;
        let req = PushRequest {
            envelope: envelope.clone(),
            ttl_secs,
        };

        let mut r = self.http.post(url).json(&req);
        if let Some(t) = &self.push_token {
            r = r.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", t));
        }

        let resp = r.send().await?;
        if !resp.status().is_success() {
            return Err(read_error(resp).await);
        }
        Ok(resp.json::<PushResponse>().await?)
    }

    pub async fn pull(
        &self,
        to: &str,
        max: Option<u32>,
        wait_ms: Option<u64>,
    ) -> Result<PullResponse> {
        let url = self.base.join("/v1/pull")?;
        let req = PullRequest {
            to: to.to_string(),
            max,
            wait_ms,
        };

        let mut r = self.http.post(url).json(&req);
        if let Some(t) = &self.pull_token {
            r = r.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", t));
        }

        let resp = r.send().await?;
        if !resp.status().is_success() {
            return Err(read_error(resp).await);
        }
        Ok(resp.json::<PullResponse>().await?)
    }

    pub async fn ack(&self, receipt: &str) -> Result<()> {
        let url = self.base.join("/v1/ack")?;
        let req = AckRequest {
            receipt: receipt.to_string(),
        };

        let mut r = self.http.post(url).json(&req);
        if let Some(t) = &self.ack_token {
            r = r.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", t));
        }

        let resp = r.send().await?;
        if !resp.status().is_success() {
            return Err(read_error(resp).await);
        }
        let body = resp.json::<AckResponse>().await?;
        if !body.ok {
            return Err(anyhow!("ack failed"));
        }
        Ok(())
    }

    pub async fn admin_stats(&self) -> Result<AdminStatsResponse> {
        let url = self.base.join("/v1/admin/stats")?;
        let mut r = self.http.get(url);
        if let Some(t) = &self.admin_token {
            r = r.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", t));
        }

        let resp = r.send().await?;
        if !resp.status().is_success() {
            return Err(read_error(resp).await);
        }
        Ok(resp.json::<AdminStatsResponse>().await?)
    }
}

pub struct MailboxClientBuilder {
    base: Url,
    tor_socks: Option<String>,
    push_token: Option<String>,
    pull_token: Option<String>,
    ack_token: Option<String>,
    admin_token: Option<String>,
    timeout: Option<std::time::Duration>,
}

impl MailboxClientBuilder {
    fn new(base_url: &str) -> Result<Self> {
        let base = Url::parse(base_url).context("invalid base_url")?;
        Ok(Self {
            base,
            tor_socks: None,
            push_token: None,
            pull_token: None,
            ack_token: None,
            admin_token: None,
            timeout: Some(std::time::Duration::from_secs(60)),
        })
    }

    /// Configure HTTP requests to go through Tor via SOCKS5h proxy.
    /// Example: `socks5h://127.0.0.1:9050`
    pub fn tor_socks(mut self, socks5h_url: impl Into<String>) -> Self {
        self.tor_socks = Some(socks5h_url.into());
        self
    }

    /// Set bearer token for mailbox push endpoint.
    pub fn push_token(mut self, token: impl Into<String>) -> Self {
        self.push_token = Some(token.into());
        self
    }

    /// Set bearer token for mailbox pull endpoint.
    pub fn pull_token(mut self, token: impl Into<String>) -> Self {
        self.pull_token = Some(token.into());
        self
    }

    /// Set bearer token for mailbox ack endpoint.
    pub fn ack_token(mut self, token: impl Into<String>) -> Self {
        self.ack_token = Some(token.into());
        self
    }

    /// Set bearer token for mailbox admin endpoints.
    pub fn admin_token(mut self, token: impl Into<String>) -> Self {
        self.admin_token = Some(token.into());
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn build(self) -> Result<MailboxClient> {
        let mut builder = Client::builder();
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(proxy_url) = &self.tor_socks {
            builder = builder.proxy(Proxy::all(proxy_url)?);
        }

        let http = builder.build()?;
        Ok(MailboxClient {
            base: self.base,
            http,
            push_token: self.push_token,
            pull_token: self.pull_token,
            ack_token: self.ack_token,
            admin_token: self.admin_token,
        })
    }
}

#[derive(Debug, Serialize)]
struct PushRequest {
    envelope: NxmsEnvelope,
    ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PushResponse {
    pub ok: bool,
    pub dedup: bool,
}

#[derive(Debug, Serialize)]
struct PullRequest {
    to: String,
    max: Option<u32>,
    wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PullResponse {
    pub ok: bool,
    pub messages: Vec<PulledMessage>,
}

#[derive(Debug, Deserialize)]
pub struct PulledMessage {
    pub receipt: String,
    pub envelope: NxmsEnvelope,
}

#[derive(Debug, Serialize)]
struct AckRequest {
    receipt: String,
}

#[derive(Debug, Deserialize)]
struct AckResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    detail: Option<String>,
    retry_after_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AdminStatsResponse {
    pub ok: bool,
    pub total_rows: u64,
    pub db_bytes: u64,
    pub wal_bytes: u64,
    pub inboxes: Vec<AdminInboxStats>,
}

#[derive(Debug, Deserialize)]
pub struct AdminInboxStats {
    pub to: String,
    pub backlog_count: u64,
    pub oldest_age_secs: u64,
    pub bytes: u64,
}

fn http_error(status: StatusCode, body: Option<String>) -> anyhow::Error {
    let mut msg = format!("mailbox http {}", status.as_u16());
    if let Some(b) = body {
        let b = b.trim();
        if !b.is_empty() {
            msg.push_str(": ");
            msg.push_str(b);
        }
    }
    anyhow!(msg)
}

async fn read_error(resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let text = resp.text().await.ok();
    if let Some(t) = &text
        && let Ok(parsed) = serde_json::from_str::<ErrorBody>(t)
    {
        let mut detail = parsed.detail.unwrap_or_default();
        if let Some(retry_after_secs) = parsed.retry_after_secs {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!("retry_after={}s", retry_after_secs));
        }
        if !detail.trim().is_empty() {
            return http_error(status, Some(detail));
        }
    }
    http_error(status, text)
}
