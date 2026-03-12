use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ACTION_TOKEN_ISSUER_SCHEMA_V1: &str = "nxms-action-token-issuer/v1";

fn default_schema() -> String {
    ACTION_TOKEN_ISSUER_SCHEMA_V1.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTokenIssuerBundle {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub issuer: String,
    pub algorithm: String,
    pub public_key_pem: String,
}

impl ActionTokenIssuerBundle {
    pub fn new(
        issuer: impl Into<String>,
        algorithm: impl Into<String>,
        public_key_pem: impl Into<String>,
    ) -> Result<Self> {
        let bundle = Self {
            schema: default_schema(),
            issuer: normalize_action_token_issuer(&issuer.into())?,
            algorithm: normalize_action_token_algorithm(&algorithm.into())?,
            public_key_pem: normalize_action_token_public_key_pem(&public_key_pem.into())?,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read(path.as_ref())?;
        let bundle: Self = serde_json::from_slice(&raw)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema.trim() != ACTION_TOKEN_ISSUER_SCHEMA_V1 {
            bail!(
                "action token issuer schema mismatch: expected '{}' got '{}'",
                ACTION_TOKEN_ISSUER_SCHEMA_V1,
                self.schema
            );
        }
        if self.issuer != normalize_action_token_issuer(&self.issuer)? {
            bail!("action token issuer must use canonical issuer formatting");
        }
        if self.algorithm != normalize_action_token_algorithm(&self.algorithm)? {
            bail!("action token issuer algorithm must be canonical uppercase");
        }
        if self.public_key_pem != normalize_action_token_public_key_pem(&self.public_key_pem)? {
            bail!("action token issuer public_key_pem must use canonical PEM formatting");
        }
        Ok(())
    }
}

pub fn normalize_action_token_issuer(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        bail!("action token issuer must be 1..=256 chars");
    }
    Ok(trimmed.to_string())
}

pub fn normalize_action_token_algorithm(value: &str) -> Result<String> {
    let trimmed = value.trim().to_ascii_uppercase();
    match trimmed.as_str() {
        "EDDSA" | "ES256" => Ok(trimmed),
        _ => bail!("action token algorithm must be EDDSA or ES256"),
    }
}

pub fn normalize_action_token_public_key_pem(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 65536 {
        bail!("action token public key PEM must be 1..=65536 chars");
    }
    if !trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        bail!("action token public key PEM must start with BEGIN PUBLIC KEY");
    }
    if !trimmed.ends_with("-----END PUBLIC KEY-----") {
        bail!("action token public key PEM must end with END PUBLIC KEY");
    }
    Ok(format!("{trimmed}\n"))
}
