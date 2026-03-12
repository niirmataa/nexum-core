use crate::action_token_issuer::{
    ActionTokenIssuerBundle, normalize_action_token_algorithm, normalize_action_token_issuer,
};
use crate::crypto::{read_secret_file, write_secret_file};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, Ed25519KeyPair, EcdsaKeyPair, KeyPair,
};
use serde::{Deserialize, Serialize};
use std::os::raw::{c_char, c_int, c_ulonglong, c_void};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const ACTION_TOKEN_ISSUER_VAULT_SCHEMA_V1: &str = "nxms-action-token-issuer-vault/v1";
const ACTION_TOKEN_ISSUER_VAULT_MAGIC: &[u8; 4] = b"NXIV";
const ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN: usize = 4 + 16 + 8 + 8 + 24 + 4;
const ACTION_TOKEN_ISSUER_VAULT_SALT_LEN: usize = 16;
const ACTION_TOKEN_ISSUER_VAULT_NONCE_LEN: usize = 24;
const ACTION_TOKEN_ISSUER_VAULT_KEY_LEN: usize = 32;
const ACTION_TOKEN_ISSUER_VAULT_MAX_CT_LEN: usize = 8 * 1024 * 1024;
const ACTION_TOKEN_ISSUER_VAULT_AEAD_TAG_LEN: usize = 16;
const ACTION_TOKEN_ISSUER_VAULT_KDF_POLICY_MULTIPLIER: usize = 8;
const CRYPTO_PWHASH_ALG_ARGON2ID13: c_int = 2;
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

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
    ACTION_TOKEN_ISSUER_VAULT_SCHEMA_V1.to_string()
}

#[derive(Debug, Deserialize)]
pub struct ActionTokenIssuerVault {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub issuer: String,
    pub algorithm: String,
    pub private_key_pem: String,
}

#[derive(Serialize)]
struct ActionTokenIssuerVaultRef<'a> {
    schema: &'static str,
    issuer: &'a str,
    algorithm: &'a str,
    private_key_pem: &'a str,
}

impl ActionTokenIssuerVault {
    pub fn generate(
        dir: impl AsRef<Path>,
        passphrase: &str,
        issuer: &str,
        algorithm: &str,
    ) -> Result<Self> {
        let dir = dir.as_ref();
        let normalized_algorithm = normalize_action_token_algorithm(algorithm)?;
        let normalized_issuer = normalize_action_token_issuer(issuer)?;
        let private_key_pem = generate_private_key_pem(&normalized_algorithm)?;
        Self::store(
            dir,
            passphrase,
            &normalized_issuer,
            &normalized_algorithm,
            &private_key_pem,
        )?;
        Self::load(dir, passphrase)
    }

    pub fn load(dir: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        init_sodium()?;
        validate_passphrase(passphrase)?;
        let path = vault_bin_path(dir.as_ref());
        let blob = read_secret_file(&path)
            .with_context(|| format!("failed to read action token issuer vault {}", path.display()))?;
        let header = VaultHeader::parse(&blob)?;
        let aad = &blob[..ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN];
        let ct = &blob[ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN..];
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
            return Err(anyhow!("action token issuer vault decrypt failed"));
        }
        plaintext.truncate(plaintext_len as usize);
        let vault: ActionTokenIssuerVault = serde_json::from_slice(plaintext.as_slice())
            .context("failed to decode action token issuer vault payload JSON")?;
        key.fill(0);
        vault.validate()?;
        Ok(vault)
    }

    pub fn store(
        dir: impl AsRef<Path>,
        passphrase: &str,
        issuer: &str,
        algorithm: &str,
        private_key_pem: &str,
    ) -> Result<()> {
        init_sodium()?;
        validate_passphrase(passphrase)?;
        let issuer = normalize_action_token_issuer(issuer)?;
        let algorithm = normalize_action_token_algorithm(algorithm)?;
        let private_key_pem = normalize_private_key_pem(private_key_pem)?;
        derive_public_bundle(&issuer, &algorithm, &private_key_pem)?;

        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).with_context(|| {
            format!("failed to create action token issuer vault dir {}", dir.display())
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || format!("failed to chmod action token issuer vault dir {}", dir.display()),
        )?;

        let mut header = VaultHeader::new();
        let payload = ActionTokenIssuerVaultRef {
            schema: ACTION_TOKEN_ISSUER_VAULT_SCHEMA_V1,
            issuer: &issuer,
            algorithm: &algorithm,
            private_key_pem: &private_key_pem,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        if plaintext.len() > ACTION_TOKEN_ISSUER_VAULT_MAX_CT_LEN {
            bail!(
                "action token issuer vault payload too large: {} > {}",
                plaintext.len(),
                ACTION_TOKEN_ISSUER_VAULT_MAX_CT_LEN
            );
        }
        let mut key = Zeroizing::new(derive_key(
            passphrase,
            &header.salt,
            header.opslimit,
            header.memlimit,
        )?);
        let mut ciphertext = Zeroizing::new(vec![0u8; plaintext.len() + 16]);
        header.ct_len = plaintext.len() + ACTION_TOKEN_ISSUER_VAULT_AEAD_TAG_LEN;
        let mut aad = Vec::with_capacity(ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN);
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
            return Err(anyhow!("action token issuer vault encrypt failed"));
        }
        ciphertext.truncate(ct_len as usize);

        let mut blob = Zeroizing::new(Vec::with_capacity(
            ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN + ciphertext.len(),
        ));
        blob.extend_from_slice(&aad);
        blob.extend_from_slice(ciphertext.as_slice());
        write_secret_file(&vault_bin_path(dir), blob.as_slice()).with_context(|| {
            format!(
                "failed to write action token issuer vault {}",
                vault_bin_path(dir).display()
            )
        })?;
        key.fill(0);
        Ok(())
    }

    pub fn export_bundle(&self, out: impl AsRef<Path>) -> Result<ActionTokenIssuerBundle> {
        let bundle = self.bundle()?;
        bundle.write_json(out)?;
        Ok(bundle)
    }

    pub fn bundle(&self) -> Result<ActionTokenIssuerBundle> {
        self.validate()?;
        derive_public_bundle(&self.issuer, &self.algorithm, &self.private_key_pem)
    }

    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema.trim() != ACTION_TOKEN_ISSUER_VAULT_SCHEMA_V1 {
            bail!(
                "action token issuer vault schema mismatch: expected '{}' got '{}'",
                ACTION_TOKEN_ISSUER_VAULT_SCHEMA_V1,
                self.schema
            );
        }
        let issuer = normalize_action_token_issuer(&self.issuer)?;
        let algorithm = normalize_action_token_algorithm(&self.algorithm)?;
        let private_key_pem = normalize_private_key_pem(&self.private_key_pem)?;
        let bundle = derive_public_bundle(&issuer, &algorithm, &private_key_pem)?;
        if bundle.issuer != issuer {
            bail!("action token issuer vault issuer mismatch");
        }
        Ok(())
    }
}

pub fn vault_bin_path(dir: &Path) -> PathBuf {
    dir.join("vault.bin")
}

fn validate_passphrase(value: &str) -> Result<()> {
    if value.trim().len() < 12 {
        bail!("action token issuer vault passphrase must be at least 12 chars");
    }
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
    salt: &[u8; ACTION_TOKEN_ISSUER_VAULT_SALT_LEN],
    opslimit: c_ulonglong,
    memlimit: usize,
) -> Result<[u8; ACTION_TOKEN_ISSUER_VAULT_KEY_LEN]> {
    let mut key = [0u8; ACTION_TOKEN_ISSUER_VAULT_KEY_LEN];
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
        bail!("action token issuer vault crypto_pwhash failed");
    }
    Ok(key)
}

struct VaultHeader {
    salt: [u8; ACTION_TOKEN_ISSUER_VAULT_SALT_LEN],
    opslimit: c_ulonglong,
    memlimit: usize,
    nonce: [u8; ACTION_TOKEN_ISSUER_VAULT_NONCE_LEN],
    ct_len: usize,
}

impl VaultHeader {
    fn new() -> Self {
        let mut salt = [0u8; ACTION_TOKEN_ISSUER_VAULT_SALT_LEN];
        let mut nonce = [0u8; ACTION_TOKEN_ISSUER_VAULT_NONCE_LEN];
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
        if blob.len() < ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN {
            bail!("action token issuer vault file too short");
        }
        if &blob[..4] != ACTION_TOKEN_ISSUER_VAULT_MAGIC {
            bail!("action token issuer vault magic mismatch");
        }
        let mut salt = [0u8; ACTION_TOKEN_ISSUER_VAULT_SALT_LEN];
        salt.copy_from_slice(&blob[4..20]);
        let opslimit = c_ulonglong::from_le_bytes(blob[20..28].try_into().expect("slice len"));
        let memlimit_raw = u64::from_le_bytes(blob[28..36].try_into().expect("slice len"));
        let memlimit = usize::try_from(memlimit_raw)
            .map_err(|_| anyhow!("action token issuer vault memlimit overflow"))?;
        validate_kdf_policy(opslimit, memlimit)?;
        let mut nonce = [0u8; ACTION_TOKEN_ISSUER_VAULT_NONCE_LEN];
        nonce.copy_from_slice(&blob[36..60]);
        let ct_len_raw = u32::from_le_bytes(blob[60..64].try_into().expect("slice len"));
        let ct_len = ct_len_raw as usize;
        if ct_len == 0 || ct_len > ACTION_TOKEN_ISSUER_VAULT_MAX_CT_LEN {
            bail!(
                "action token issuer vault ciphertext length out of bounds: {}",
                ct_len
            );
        }
        if blob.len() != ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN + ct_len {
            bail!(
                "action token issuer vault size mismatch: blob={} expected={}",
                blob.len(),
                ACTION_TOKEN_ISSUER_VAULT_HEADER_LEN + ct_len
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
        out.extend_from_slice(ACTION_TOKEN_ISSUER_VAULT_MAGIC);
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
    let max_opslimit =
        baseline_opslimit.saturating_mul(ACTION_TOKEN_ISSUER_VAULT_KDF_POLICY_MULTIPLIER as u64);
    let max_memlimit =
        baseline_memlimit.saturating_mul(ACTION_TOKEN_ISSUER_VAULT_KDF_POLICY_MULTIPLIER);
    if opslimit == 0 || opslimit > max_opslimit {
        bail!(
            "action token issuer vault opslimit {} exceeds policy max {}",
            opslimit,
            max_opslimit
        );
    }
    if memlimit == 0 || memlimit > max_memlimit {
        bail!(
            "action token issuer vault memlimit {} exceeds policy max {}",
            memlimit,
            max_memlimit
        );
    }
    Ok(())
}

fn generate_private_key_pem(algorithm: &str) -> Result<String> {
    let algorithm = normalize_action_token_algorithm(algorithm)?;
    let rng = SystemRandom::new();
    let pkcs8 = match algorithm.as_str() {
        "EDDSA" => Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("failed to generate Ed25519 action token issuer key"))?
            .as_ref()
            .to_vec(),
        "ES256" => EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("failed to generate P-256 action token issuer key"))?
            .as_ref()
            .to_vec(),
        _ => bail!("unsupported action token algorithm '{}'", algorithm),
    };
    Ok(encode_pem("PRIVATE KEY", &pkcs8))
}

fn derive_public_bundle(
    issuer: &str,
    algorithm: &str,
    private_key_pem: &str,
) -> Result<ActionTokenIssuerBundle> {
    let issuer = normalize_action_token_issuer(issuer)?;
    let algorithm = normalize_action_token_algorithm(algorithm)?;
    let private_key_pem = normalize_private_key_pem(private_key_pem)?;
    let private_key_der = decode_pem("PRIVATE KEY", &private_key_pem)?;
    let public_der = derive_public_key_der(&algorithm, &private_key_der)?;
    ActionTokenIssuerBundle::new(issuer, algorithm, encode_pem("PUBLIC KEY", &public_der))
}

fn derive_public_key_der(algorithm: &str, private_key_der: &[u8]) -> Result<Vec<u8>> {
    let algorithm = normalize_action_token_algorithm(algorithm)?;
    let rng = SystemRandom::new();
    match algorithm.as_str() {
        "EDDSA" => {
            let pair = Ed25519KeyPair::from_pkcs8(private_key_der)
                .map_err(|_| anyhow!("failed to parse Ed25519 action token issuer key"))?;
            if pair.public_key().as_ref().len() != 32 {
                bail!("unexpected Ed25519 public key length");
            }
            let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
            der.extend_from_slice(ED25519_SPKI_PREFIX);
            der.extend_from_slice(pair.public_key().as_ref());
            Ok(der)
        }
        "ES256" => {
            let pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                private_key_der,
                &rng,
            )
            .map_err(|_| anyhow!("failed to parse ES256 action token issuer key"))?;
            let public_key = pair.public_key().as_ref();
            if public_key.len() != 65 || public_key.first().copied() != Some(0x04) {
                bail!("unexpected P-256 public key encoding");
            }
            let mut der = Vec::with_capacity(P256_SPKI_PREFIX.len() + public_key.len());
            der.extend_from_slice(P256_SPKI_PREFIX);
            der.extend_from_slice(public_key);
            Ok(der)
        }
        _ => bail!("unsupported action token algorithm '{}'", algorithm),
    }
}

fn normalize_private_key_pem(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 65536 {
        bail!("action token private key PEM must be 1..=65536 chars");
    }
    if !trimmed.starts_with("-----BEGIN PRIVATE KEY-----") {
        bail!("action token private key PEM must start with BEGIN PRIVATE KEY");
    }
    if !trimmed.ends_with("-----END PRIVATE KEY-----") {
        bail!("action token private key PEM must end with END PRIVATE KEY");
    }
    Ok(format!("{trimmed}\n"))
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 chunk"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn decode_pem(label: &str, pem: &str) -> Result<Vec<u8>> {
    let pem = pem.trim();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    if !pem.starts_with(&begin) || !pem.ends_with(&end) {
        bail!("PEM does not contain expected {} wrapper", label);
    }
    let inner = pem
        .strip_prefix(&begin)
        .and_then(|v| v.strip_suffix(&end))
        .ok_or_else(|| anyhow!("PEM wrapper parse failed for {}", label))?;
    let b64: String = inner.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
    if b64.is_empty() {
        bail!("PEM body is empty for {}", label);
    }
    STANDARD
        .decode(b64.as_bytes())
        .map_err(|err| anyhow!("PEM base64 decode failed for {}: {}", label, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    struct TestClaims {
        sub: String,
        exp: u64,
    }

    fn unique_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxms_action_token_issuer_vault_{}_{}_{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn roundtrip_sign_and_verify(vault: &ActionTokenIssuerVault) {
        let bundle = vault.bundle().expect("bundle");
        let claims = TestClaims {
            sub: "test".to_string(),
            exp: 4_102_444_800,
        };
        let token = match bundle.algorithm.as_str() {
            "EDDSA" => encode(
                &Header::new(Algorithm::EdDSA),
                &claims,
                &EncodingKey::from_ed_pem(vault.private_key_pem().as_bytes()).expect("ed key"),
            )
            .expect("encode ed"),
            "ES256" => encode(
                &Header::new(Algorithm::ES256),
                &claims,
                &EncodingKey::from_ec_pem(vault.private_key_pem().as_bytes()).expect("ec key"),
            )
            .expect("encode ec"),
            other => panic!("unexpected algorithm {other}"),
        };
        let decoding_key = match bundle.algorithm.as_str() {
            "EDDSA" => {
                DecodingKey::from_ed_pem(bundle.public_key_pem.as_bytes()).expect("ed decode")
            }
            "ES256" => {
                DecodingKey::from_ec_pem(bundle.public_key_pem.as_bytes()).expect("ec decode")
            }
            other => panic!("unexpected algorithm {other}"),
        };
        let decoded = decode::<TestClaims>(
            &token,
            &decoding_key,
            &Validation::new(match bundle.algorithm.as_str() {
                "EDDSA" => Algorithm::EdDSA,
                "ES256" => Algorithm::ES256,
                _ => unreachable!(),
            }),
        )
        .expect("decode");
        assert_eq!(decoded.claims.sub, "test");
    }

    #[test]
    fn action_token_issuer_vault_roundtrip_eddsa() {
        let dir = unique_dir("eddsa");
        let vault = ActionTokenIssuerVault::generate(&dir, "correct horse battery", "nxms-auth", "EDDSA")
            .expect("generate");
        let loaded = ActionTokenIssuerVault::load(&dir, "correct horse battery").expect("load");
        assert_eq!(loaded.issuer, "nxms-auth");
        assert_eq!(loaded.algorithm, "EDDSA");
        roundtrip_sign_and_verify(&vault);
        roundtrip_sign_and_verify(&loaded);
        let _ = std::fs::remove_file(vault_bin_path(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn action_token_issuer_vault_roundtrip_es256() {
        let dir = unique_dir("es256");
        let vault = ActionTokenIssuerVault::generate(&dir, "correct horse battery", "nxms-auth", "ES256")
            .expect("generate");
        roundtrip_sign_and_verify(&vault);
        let _ = std::fs::remove_file(vault_bin_path(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn action_token_issuer_vault_rejects_wrong_passphrase() {
        let dir = unique_dir("wrong_pass");
        ActionTokenIssuerVault::generate(&dir, "correct horse battery", "nxms-auth", "EDDSA")
            .expect("generate");
        let err = ActionTokenIssuerVault::load(&dir, "wrong passphrase")
            .expect_err("wrong passphrase should fail");
        assert!(err.to_string().contains("decrypt failed"));
        let _ = std::fs::remove_file(vault_bin_path(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn action_token_issuer_vault_rejects_memlimit_above_policy_cap() {
        let dir = unique_dir("memlimit");
        ActionTokenIssuerVault::generate(&dir, "correct horse battery", "nxms-auth", "EDDSA")
            .expect("generate");
        let path = vault_bin_path(&dir);
        let mut blob = std::fs::read(&path).expect("read vault");
        let baseline_memlimit = unsafe { crypto_pwhash_memlimit_interactive() };
        let oversized = baseline_memlimit
            .saturating_mul(ACTION_TOKEN_ISSUER_VAULT_KDF_POLICY_MULTIPLIER + 1)
            as u64;
        blob[28..36].copy_from_slice(&oversized.to_le_bytes());
        std::fs::write(&path, blob).expect("write tampered vault");
        let err = ActionTokenIssuerVault::load(&dir, "correct horse battery")
            .expect_err("oversized memlimit must fail");
        assert!(err.to_string().contains("memlimit"));
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(&dir);
    }
}
