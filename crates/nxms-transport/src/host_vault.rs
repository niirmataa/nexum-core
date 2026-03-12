use crate::crypto::{Keys, read_secret_file, suite_kem_id, suite_sig_id, write_secret_file};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::os::raw::{c_char, c_int, c_ulonglong, c_void};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const HOST_VAULT_SCHEMA_V1: &str = "nxms-host-vault/v1";
const HOST_VAULT_MAGIC: &[u8; 4] = b"NXHV";
const HOST_VAULT_HEADER_LEN: usize = 4 + 16 + 8 + 8 + 24 + 4;
const HOST_VAULT_SALT_LEN: usize = 16;
const HOST_VAULT_NONCE_LEN: usize = 24;
const HOST_VAULT_KEY_LEN: usize = 32;
const HOST_VAULT_MAX_CT_LEN: usize = 16 * 1024 * 1024;
const HOST_VAULT_AEAD_TAG_LEN: usize = 16;
const HOST_VAULT_KDF_POLICY_MULTIPLIER: usize = 8;
const CRYPTO_PWHASH_ALG_ARGON2ID13: c_int = 2;

unsafe extern "C" {
    fn sodium_init() -> c_int;
    fn sodium_memzero(pnt: *mut c_void, len: usize);
    fn randombytes_buf(buf: *mut c_void, size: usize);
    fn crypto_pwhash(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const c_char,
        passwdlen: c_ulonglong,
        salt: *const u8,
        opslimit: c_ulonglong,
        memlimit: usize,
        alg: c_int,
    ) -> c_int;
    fn crypto_pwhash_opslimit_interactive() -> c_ulonglong;
    fn crypto_pwhash_memlimit_interactive() -> usize;
    fn crypto_aead_xchacha20poly1305_ietf_encrypt(
        c: *mut u8,
        clen_p: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const u8,
        npub: *const u8,
        k: *const u8,
    ) -> c_int;
    fn crypto_aead_xchacha20poly1305_ietf_decrypt(
        m: *mut u8,
        mlen_p: *mut c_ulonglong,
        nsec: *mut u8,
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const u8,
        k: *const u8,
    ) -> c_int;
}

fn default_schema() -> String {
    HOST_VAULT_SCHEMA_V1.to_string()
}

#[derive(Debug, Deserialize)]
pub struct HostVault {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub local_id: String,
    pub kem_id: String,
    pub sig_id: String,
    pub keys: Keys,
}

#[derive(Serialize)]
struct HostVaultRef<'a> {
    schema: &'static str,
    local_id: &'a str,
    kem_id: &'static str,
    sig_id: &'static str,
    keys: &'a Keys,
}

impl HostVault {
    pub fn generate(dir: impl AsRef<Path>, passphrase: &str, local_id: &str) -> Result<Self> {
        let dir = dir.as_ref();
        let keys = Keys::generate()?;
        Self::store(dir, passphrase, local_id, &keys)?;
        Self::load(dir, passphrase)
    }

    pub fn load(dir: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        init_sodium()?;
        validate_passphrase(passphrase)?;
        let path = vault_bin_path(dir.as_ref());
        let blob = read_secret_file(&path)
            .with_context(|| format!("failed to read host vault {}", path.display()))?;
        let header = VaultHeader::parse(&blob)?;
        let aad = &blob[..HOST_VAULT_HEADER_LEN];
        let ct = &blob[HOST_VAULT_HEADER_LEN..];
        let mut key = Zeroizing::new(derive_key(
            passphrase,
            &header.salt,
            header.opslimit,
            header.memlimit,
        )?);
        let mut plaintext = Zeroizing::new(vec![0u8; header.ct_len]);
        let mut plaintext_len: c_ulonglong = 0;
        let rc = unsafe {
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.as_mut_ptr(),
                &mut plaintext_len,
                std::ptr::null_mut(),
                ct.as_ptr(),
                ct.len() as c_ulonglong,
                aad.as_ptr(),
                aad.len() as c_ulonglong,
                header.nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(anyhow!("host vault decrypt failed"));
        }
        plaintext.truncate(plaintext_len as usize);
        let vault: HostVault = serde_json::from_slice(plaintext.as_slice())
            .context("failed to decode host vault payload JSON")?;
        key.fill(0);
        vault.validate()?;
        Ok(vault)
    }

    pub fn store(
        dir: impl AsRef<Path>,
        passphrase: &str,
        local_id: &str,
        keys: &Keys,
    ) -> Result<()> {
        init_sodium()?;
        validate_passphrase(passphrase)?;
        validate_local_id(local_id)?;
        validate_keys(keys)?;

        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create host vault dir {}", dir.display()))?;
        #[cfg(unix)]
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || format!("failed to chmod host vault dir {}", dir.display()),
        )?;

        let mut header = VaultHeader::new();
        let payload = HostVaultRef {
            schema: HOST_VAULT_SCHEMA_V1,
            local_id,
            kem_id: suite_kem_id(),
            sig_id: suite_sig_id(),
            keys,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        if plaintext.len() > HOST_VAULT_MAX_CT_LEN {
            bail!(
                "host vault payload too large: {} > {}",
                plaintext.len(),
                HOST_VAULT_MAX_CT_LEN
            );
        }
        let mut key = Zeroizing::new(derive_key(
            passphrase,
            &header.salt,
            header.opslimit,
            header.memlimit,
        )?);
        let mut ciphertext = Zeroizing::new(vec![0u8; plaintext.len() + 16]);
        header.ct_len = plaintext.len() + HOST_VAULT_AEAD_TAG_LEN;
        let mut aad = Vec::with_capacity(HOST_VAULT_HEADER_LEN);
        header.write_into(&mut aad);
        let mut ct_len: c_ulonglong = 0;
        let rc = unsafe {
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(),
                &mut ct_len,
                plaintext.as_ptr(),
                plaintext.len() as c_ulonglong,
                aad.as_ptr(),
                aad.len() as c_ulonglong,
                std::ptr::null(),
                header.nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(anyhow!("host vault encrypt failed"));
        }
        ciphertext.truncate(ct_len as usize);

        let mut blob = Zeroizing::new(Vec::with_capacity(HOST_VAULT_HEADER_LEN + ciphertext.len()));
        blob.extend_from_slice(&aad);
        blob.extend_from_slice(ciphertext.as_slice());
        write_secret_file(&vault_bin_path(dir), blob.as_slice()).with_context(|| {
            format!(
                "failed to write host vault {}",
                vault_bin_path(dir).display()
            )
        })?;
        key.fill(0);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema.trim() != HOST_VAULT_SCHEMA_V1 {
            bail!(
                "host vault schema mismatch: expected '{}' got '{}'",
                HOST_VAULT_SCHEMA_V1,
                self.schema
            );
        }
        validate_local_id(&self.local_id)?;
        if self.kem_id.trim() != suite_kem_id() {
            bail!(
                "host vault kem_id '{}' does not match runtime suite '{}'",
                self.kem_id,
                suite_kem_id()
            );
        }
        if self.sig_id.trim() != suite_sig_id() {
            bail!(
                "host vault sig_id '{}' does not match runtime suite '{}'",
                self.sig_id,
                suite_sig_id()
            );
        }
        validate_keys(&self.keys)?;
        Ok(())
    }
}

pub fn load_host_keys(dir: impl AsRef<Path>, passphrase: &str) -> Result<Keys> {
    Ok(HostVault::load(dir, passphrase)?.keys)
}

pub fn vault_bin_path(dir: &Path) -> PathBuf {
    dir.join("vault.bin")
}

fn validate_local_id(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        bail!("host vault local_id must be 1..=128 chars");
    }
    Ok(())
}

fn validate_passphrase(value: &str) -> Result<()> {
    if value.trim().len() < 12 {
        bail!("host vault passphrase must be at least 12 chars");
    }
    Ok(())
}

fn validate_keys(keys: &Keys) -> Result<()> {
    let _ = keys.kem_pk()?;
    let _ = keys.sig_pk()?;
    let _ = keys.kem_sk_zeroizing()?;
    let _ = keys.sig_sk_zeroizing()?;
    Ok(())
}

fn init_sodium() -> Result<()> {
    let rc = unsafe { sodium_init() };
    if rc < 0 {
        bail!("sodium_init failed");
    }
    Ok(())
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; HOST_VAULT_SALT_LEN],
    opslimit: c_ulonglong,
    memlimit: usize,
) -> Result<[u8; HOST_VAULT_KEY_LEN]> {
    let mut key = [0u8; HOST_VAULT_KEY_LEN];
    let rc = unsafe {
        crypto_pwhash(
            key.as_mut_ptr(),
            key.len() as c_ulonglong,
            passphrase.as_ptr().cast::<c_char>(),
            passphrase.len() as c_ulonglong,
            salt.as_ptr(),
            opslimit,
            memlimit,
            CRYPTO_PWHASH_ALG_ARGON2ID13,
        )
    };
    if rc != 0 {
        unsafe { sodium_memzero(key.as_mut_ptr().cast::<c_void>(), key.len()) };
        bail!("host vault crypto_pwhash failed");
    }
    Ok(key)
}

struct VaultHeader {
    salt: [u8; HOST_VAULT_SALT_LEN],
    opslimit: c_ulonglong,
    memlimit: usize,
    nonce: [u8; HOST_VAULT_NONCE_LEN],
    ct_len: usize,
}

impl VaultHeader {
    fn new() -> Self {
        let mut salt = [0u8; HOST_VAULT_SALT_LEN];
        let mut nonce = [0u8; HOST_VAULT_NONCE_LEN];
        unsafe {
            randombytes_buf(salt.as_mut_ptr().cast::<c_void>(), salt.len());
            randombytes_buf(nonce.as_mut_ptr().cast::<c_void>(), nonce.len());
        }
        Self {
            salt,
            opslimit: unsafe { crypto_pwhash_opslimit_interactive() },
            memlimit: unsafe { crypto_pwhash_memlimit_interactive() },
            nonce,
            ct_len: 0,
        }
    }

    fn parse(blob: &[u8]) -> Result<Self> {
        if blob.len() < HOST_VAULT_HEADER_LEN {
            bail!("host vault file too short");
        }
        if &blob[..4] != HOST_VAULT_MAGIC {
            bail!("host vault magic mismatch");
        }
        let mut salt = [0u8; HOST_VAULT_SALT_LEN];
        salt.copy_from_slice(&blob[4..20]);
        let opslimit = c_ulonglong::from_le_bytes(blob[20..28].try_into().expect("slice len"));
        let memlimit_raw = u64::from_le_bytes(blob[28..36].try_into().expect("slice len"));
        let memlimit = usize::try_from(memlimit_raw).map_err(|_| anyhow!("host vault memlimit overflow"))?;
        validate_kdf_policy(opslimit, memlimit)?;
        let mut nonce = [0u8; HOST_VAULT_NONCE_LEN];
        nonce.copy_from_slice(&blob[36..60]);
        let ct_len_raw = u32::from_le_bytes(blob[60..64].try_into().expect("slice len"));
        let ct_len = ct_len_raw as usize;
        if ct_len == 0 || ct_len > HOST_VAULT_MAX_CT_LEN {
            bail!("host vault ciphertext length out of bounds: {}", ct_len);
        }
        if blob.len() != HOST_VAULT_HEADER_LEN + ct_len {
            bail!(
                "host vault size mismatch: blob={} expected={}",
                blob.len(),
                HOST_VAULT_HEADER_LEN + ct_len
            );
        }
        Ok(Self {
            salt,
            opslimit,
            memlimit,
            nonce,
            ct_len,
        })
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(HOST_VAULT_MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.opslimit.to_le_bytes());
        out.extend_from_slice(&(self.memlimit as u64).to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ct_len as u32).to_le_bytes());
    }
}

fn validate_kdf_policy(opslimit: c_ulonglong, memlimit: usize) -> Result<()> {
    let baseline_opslimit = unsafe { crypto_pwhash_opslimit_interactive() };
    let baseline_memlimit = unsafe { crypto_pwhash_memlimit_interactive() };
    let max_opslimit = baseline_opslimit.saturating_mul(HOST_VAULT_KDF_POLICY_MULTIPLIER as u64);
    let max_memlimit = baseline_memlimit.saturating_mul(HOST_VAULT_KDF_POLICY_MULTIPLIER);
    if opslimit == 0 || opslimit > max_opslimit {
        bail!(
            "host vault opslimit {} exceeds policy max {}",
            opslimit,
            max_opslimit
        );
    }
    if memlimit == 0 || memlimit > max_memlimit {
        bail!(
            "host vault memlimit {} exceeds policy max {}",
            memlimit,
            max_memlimit
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_vault_roundtrip_preserves_keys() {
        let dir = std::env::temp_dir().join(format!(
            "nxms_host_vault_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let keys = Keys::generate().expect("keys");
        HostVault::store(&dir, "correct horse battery", "signer-a", &keys).expect("store");
        let loaded = HostVault::load(&dir, "correct horse battery").expect("load");
        assert_eq!(loaded.local_id, "signer-a");
        assert_eq!(loaded.kem_id, suite_kem_id());
        assert_eq!(loaded.sig_id, suite_sig_id());
        assert_eq!(loaded.keys.kem_pk_b64, keys.kem_pk_b64);
        assert_eq!(loaded.keys.sig_pk_b64, keys.sig_pk_b64);
        assert_eq!(
            loaded.keys.kem_sk_zeroizing().expect("loaded kem sk").as_slice(),
            keys.kem_sk_zeroizing().expect("kem sk").as_slice()
        );
        assert_eq!(
            loaded.keys.sig_sk_zeroizing().expect("loaded sig sk").as_slice(),
            keys.sig_sk_zeroizing().expect("sig sk").as_slice()
        );
        let _ = std::fs::remove_file(vault_bin_path(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn host_vault_rejects_wrong_passphrase() {
        let dir = std::env::temp_dir().join(format!(
            "nxms_host_vault_bad_pass_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        HostVault::generate(&dir, "correct horse battery", "signer-a").expect("generate");
        let err = HostVault::load(&dir, "wrong passphrase")
            .expect_err("wrong passphrase should fail");
        assert!(err.to_string().contains("decrypt failed"));
        let _ = std::fs::remove_file(vault_bin_path(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn host_vault_rejects_memlimit_above_policy_cap() {
        let dir = std::env::temp_dir().join(format!(
            "nxms_host_vault_memlimit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        HostVault::generate(&dir, "correct horse battery", "signer-a").expect("generate");
        let path = vault_bin_path(&dir);
        let mut blob = std::fs::read(&path).expect("read vault");
        let baseline_memlimit = unsafe { crypto_pwhash_memlimit_interactive() };
        let oversized = baseline_memlimit
            .saturating_mul(HOST_VAULT_KDF_POLICY_MULTIPLIER + 1) as u64;
        blob[28..36].copy_from_slice(&oversized.to_le_bytes());
        std::fs::write(&path, blob).expect("write tampered vault");
        let err =
            HostVault::load(&dir, "correct horse battery").expect_err("oversized memlimit must fail");
        assert!(err.to_string().contains("memlimit"));
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(&dir);
    }
}
