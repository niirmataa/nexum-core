//! Integration tests for `nxms-host-bootstrap admission` — building and
//! guard-signing escrow admission artifacts against a runtime trust bundle.

use nxms_transport::admission::EscrowAdmissionArtifact;
use nxms_transport::crypto::Keys;
use nxms_transport::host_identity::HostIdentityBundle;
use nxms_transport::host_vault::HostVault;
use nxms_transport::trust::{RuntimeActionTokenIssuer, RuntimeTrustBundle};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const PASSPHRASE: &str = "correct horse battery";
const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";
const ESCROW_ID_HEX: &str = "00112233445566778899aabbccddeeff";

fn snapshot_hash() -> String {
    "11".repeat(32)
}

struct Fixture {
    _tmp: TempDir,
    bundle_path: PathBuf,
    vault_a: PathBuf,
    vault_b: PathBuf,
    pass_file: PathBuf,
    trust_epoch: String,
}

fn fixture() -> Fixture {
    let tmp = TempDir::new().expect("tempdir");
    let keys_a = Keys::generate().expect("keys ag-01");
    let keys_b = Keys::generate().expect("keys ag-02");
    let vault_a = tmp.path().join("vault-a");
    let vault_b = tmp.path().join("vault-b");
    HostVault::store(&vault_a, PASSPHRASE, "signer_a", &keys_a).expect("store vault a");
    HostVault::store(&vault_b, PASSPHRASE, "signer_b", &keys_b).expect("store vault b");
    let pass_file = tmp.path().join("guard.pass");
    std::fs::write(&pass_file, format!("{PASSPHRASE}\n")).expect("write passphrase");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pass_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod passphrase");
    }

    let trust_epoch = "epoch-admission-cli-test".to_string();
    let identities = vec![
        HostIdentityBundle::from_local_keys("signer_a", "ag-01", "a.onion", 80, &keys_a)
            .expect("identity ag-01"),
        HostIdentityBundle::from_local_keys("signer_b", "ag-02", "b.onion", 80, &keys_b)
            .expect("identity ag-02"),
    ];
    let issuer = RuntimeActionTokenIssuer {
        issuer: "nxms-auth".to_string(),
        algorithm: "EDDSA".to_string(),
        public_key_pem: ED25519_PUBLIC_PEM.to_string(),
    };
    let mut bundle = RuntimeTrustBundle::from_host_identities(&trust_epoch, &identities, issuer)
        .expect("bundle");
    bundle
        .sign_with_local_keys("signer_a", "ag-01", &keys_a, 1)
        .expect("bundle sign ag-01");
    bundle
        .sign_with_local_keys("signer_b", "ag-02", &keys_b, 2)
        .expect("bundle sign ag-02");
    let bundle_path = tmp.path().join("runtime-trust.final.json");
    bundle.write_json(&bundle_path).expect("write bundle");

    Fixture {
        _tmp: tmp,
        bundle_path,
        vault_a,
        vault_b,
        pass_file,
        trust_epoch,
    }
}

fn run_admission(
    fixture: &Fixture,
    vault_dir: &Path,
    input: Option<&Path>,
    out: &Path,
    snapshot_hash_hex: &str,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nxms-host-bootstrap"));
    cmd.arg("admission")
        .arg("--bundle")
        .arg(&fixture.bundle_path)
        .arg("--escrow-id")
        .arg(ESCROW_ID_HEX)
        .arg("--snapshot-hash")
        .arg(snapshot_hash_hex)
        .arg("--action")
        .arg("release")
        .arg("--host-vault-dir")
        .arg(vault_dir)
        .arg("--host-vault-passphrase-file")
        .arg(&fixture.pass_file)
        .arg("--out")
        .arg(out);
    if let Some(input) = input {
        cmd.arg("--in").arg(input);
    }
    cmd.output().expect("run nxms-host-bootstrap admission")
}

/// The command prints a trailing JSON summary after optional status lines.
fn summary_json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    for start in (0..lines.len()).rev() {
        if lines[start].starts_with('{') {
            let candidate = lines[start..].join("\n");
            if let Ok(value) = serde_json::from_str(&candidate) {
                return value;
            }
        }
    }
    panic!("no JSON summary in stdout: {stdout}");
}

fn load_artifact(path: &Path) -> EscrowAdmissionArtifact {
    let raw = std::fs::read(path).expect("read artifact");
    serde_json::from_slice(&raw).expect("parse artifact")
}

#[test]
fn admission_cli_builds_and_verifies_artifact_after_both_guard_signatures() {
    let fx = fixture();
    let out = fx.bundle_path.parent().unwrap().join("admission.json");

    // First guard (ag-01): creates the artifact with one signature.
    let first = run_admission(&fx, &fx.vault_a, None, &out, &snapshot_hash());
    assert!(
        first.status.success(),
        "first guard call failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary1 = summary_json(&first);
    assert_eq!(summary1["verified"], serde_json::json!(false));
    assert_eq!(summary1["signatures"].as_array().expect("sigs").len(), 1);
    assert_eq!(summary1["signatures"][0]["signer_id"], "signer_a");
    assert_eq!(summary1["signatures"][0]["signer_role"], "ag-01");
    assert_eq!(summary1["signatures"][0]["alg"], "Falcon-1024-CT");
    assert_eq!(summary1["runtime_trust_epoch"], fx.trust_epoch.as_str());

    // Second guard (ag-02): adds its signature to the same artifact.
    let second = run_admission(&fx, &fx.vault_b, Some(&out), &out, &snapshot_hash());
    assert!(
        second.status.success(),
        "second guard call failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let summary2 = summary_json(&second);
    assert_eq!(summary2["verified"], serde_json::json!(true));
    assert_eq!(summary2["signatures"].as_array().expect("sigs").len(), 2);

    let artifact = load_artifact(&out);
    let bundle = RuntimeTrustBundle::load_verified(&fx.bundle_path).expect("load bundle");
    artifact
        .verify_against_bundle(&bundle)
        .expect("completed artifact must verify against the bundle");
    assert_eq!(artifact.snapshot_hash_hex, snapshot_hash());
    assert_eq!(artifact.runtime_trust_epoch, fx.trust_epoch);
    assert_eq!(summary2["artifact_hash_hex"], artifact.hash_hex().expect("hash"));
}

#[test]
fn admission_cli_single_guard_signature_is_rejected_by_bundle_verification() {
    let fx = fixture();
    let out = fx.bundle_path.parent().unwrap().join("admission.json");
    let first = run_admission(&fx, &fx.vault_a, None, &out, &snapshot_hash());
    assert!(first.status.success());

    let artifact = load_artifact(&out);
    let bundle = RuntimeTrustBundle::load_verified(&fx.bundle_path).expect("load bundle");
    let err = artifact
        .verify_against_bundle(&bundle)
        .expect_err("single guard signature must not verify");
    assert!(
        err.to_string().contains("requires exactly 2 guard signatures"),
        "unexpected error: {err}"
    );
}

#[test]
fn admission_cli_rejects_in_artifact_bound_to_different_snapshot_hash() {
    let fx = fixture();
    let out = fx.bundle_path.parent().unwrap().join("admission.json");
    let first = run_admission(&fx, &fx.vault_a, None, &out, &snapshot_hash());
    assert!(first.status.success());

    // Second guard tries to continue the artifact under another snapshot hash.
    let other_hash = "22".repeat(32);
    let second = run_admission(&fx, &fx.vault_b, Some(&out), &out, &other_hash);
    assert!(
        !second.status.success(),
        "mismatched --snapshot-hash must be rejected"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("snapshot_hash mismatch"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn admission_cli_artifact_with_tampered_snapshot_hash_fails_verification() {
    let fx = fixture();
    let out = fx.bundle_path.parent().unwrap().join("admission.json");
    assert!(run_admission(&fx, &fx.vault_a, None, &out, &snapshot_hash()).status.success());
    assert!(run_admission(&fx, &fx.vault_b, Some(&out), &out, &snapshot_hash()).status.success());

    // Tamper with a signed field: the guard signatures must reject it.
    let mut artifact = load_artifact(&out);
    artifact.snapshot_hash_hex = "22".repeat(32);
    let bundle = RuntimeTrustBundle::load_verified(&fx.bundle_path).expect("load bundle");
    let err = artifact
        .verify_against_bundle(&bundle)
        .expect_err("tampered snapshot_hash must not verify");
    assert!(
        err.to_string().contains("signature hash mismatch"),
        "unexpected error: {err}"
    );
}
