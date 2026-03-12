use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(feature = "crypto")]
use crate::crypto::Keys;

const HOST_IDENTITY_SCHEMA_V1: &str = "nxms-host-identity/v1";

fn default_schema() -> String {
    HOST_IDENTITY_SCHEMA_V1.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentityBundle {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub host_id: String,
    pub role: String,
    pub host: String,
    pub port: u16,
    pub kem_pk_b64: String,
    pub sig_pk_b64: String,
}

impl HostIdentityBundle {
    #[cfg(feature = "crypto")]
    pub fn from_local_keys(
        host_id: impl Into<String>,
        role: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        keys: &Keys,
    ) -> Result<Self> {
        let bundle = Self {
            schema: default_schema(),
            host_id: host_id.into(),
            role: role.into(),
            host: host.into(),
            port,
            kem_pk_b64: keys.kem_pk_b64.clone(),
            sig_pk_b64: keys.sig_pk_b64.clone(),
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
        if self.schema.trim() != HOST_IDENTITY_SCHEMA_V1 {
            bail!(
                "host identity schema mismatch: expected '{}' got '{}'",
                HOST_IDENTITY_SCHEMA_V1,
                self.schema
            );
        }
        validate_text(&self.host_id, "host_id", 128)?;
        validate_text(&self.role, "role", 128)?;
        validate_hidden_service_host(&self.host)?;
        if self.port == 0 {
            bail!("host identity port must be > 0");
        }
        validate_text(&self.kem_pk_b64, "kem_pk_b64", 65536)?;
        validate_text(&self.sig_pk_b64, "sig_pk_b64", 65536)?;
        Ok(())
    }
}

fn validate_text(value: &str, field: &str, max_len: usize) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        bail!("{field} must be 1..={max_len} chars");
    }
    Ok(())
}

fn validate_hidden_service_host(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 255 {
        bail!("host identity host must be 1..=255 chars");
    }
    if trimmed.contains("://") {
        bail!("host identity host must be onion host only, not URL");
    }
    if !trimmed.ends_with(".onion") {
        bail!("host identity host must be Tor hidden service (.onion)");
    }
    Ok(())
}
