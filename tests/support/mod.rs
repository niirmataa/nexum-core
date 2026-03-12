#![allow(dead_code)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nxms_mailbox::{
    api::ApiConfig as MailboxApiConfig,
    build_app as build_mailbox_app,
    db::{MailboxLimits as MailboxDbLimits, SqliteMailboxDb as RealMailboxDb},
    AppState as MailboxAppState,
};
use nxms_mailbox_client::MailboxClient;
use nxms_signer::{
    action_token::{sign_req_id, ActionClaims},
    config::{ActionTokenConfig, SignerConfig, SignerRole, WalletRpcConfig},
    db::{SignerDb, SnapshotSigRow},
    snapshot::{
        canonical_hash_hex, canonical_policy_hash_sha256_hex, AmountRule, Asset, ContractSnapshot,
        PayoutPolicy, RecipientRule,
    },
    SignerAgent,
};
use nxms_transport::admission::EscrowAdmissionArtifact;
use nxms_transport::crypto::{decrypt, encrypt, suite_kem_id, suite_sig_id, Keys, SealedPacket};
use nxms_transport::host_vault::HostVault;
use nxms_transport::peers::{Peer, PeerBook};
use nxms_transport::trust::{RuntimeActionTokenIssuer, RuntimeTrustBundle, RuntimeTrustPeer};
use nxms_transport::wire::{
    msg_type_key, EscrowAction, EscrowBody, MsgType, NxmsEnvelope, NxmsPayload, TxSignReqBody,
    ESCROW_APP_PROTO_V1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCBxRIEv7DU1o/rRG+beqeRLVa2kL9RAArTq6vRp7D0\n-----END PRIVATE KEY-----\n";
const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";
const BRIDGE_TOKEN_ENV: &str = "NXMS_SIGNER_ORCH_BRIDGE_TOKEN";
const TEST_BRIDGE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct WalletMockState {
    calls: Mutex<Vec<String>>,
}

pub struct WorkspaceSignerHarness {
    _tempdir: TempDir,
    pub agent: Arc<SignerAgent>,
    pub cfg: SignerConfig,
    pub db: SignerDb,
    pub local_keys: Keys,
    pub peer_keys: Keys,
    pub ag01_keys: Keys,
    pub ag02_keys: Keys,
    pub mailbox_url: String,
    wallet_state: Arc<WalletMockState>,
}

impl WorkspaceSignerHarness {
    pub async fn setup() -> Result<Self> {
        std::env::set_var(BRIDGE_TOKEN_ENV, TEST_BRIDGE_TOKEN);

        let tempdir = TempDir::new().context("tempdir")?;
        let mailbox_url = spawn_real_mailbox_server(&tempdir).await?;
        let wallet_state = Arc::new(WalletMockState::default());
        let wallet_url = spawn_http_server(
            Router::new()
                .route("/json_rpc", post(wallet_rpc_handler))
                .with_state(wallet_state.clone()),
        )
        .await?;

        let local_keys = Keys::generate().context("generate local keys")?;
        let peer_keys = Keys::generate().context("generate peer keys")?;
        let ag01_keys = Keys::generate().context("generate ag01 keys")?;
        let ag02_keys = Keys::generate().context("generate ag02 keys")?;
        let host_vault_dir = tempdir.path().join("host-vault");
        let peers_path = tempdir.path().join("peers.json");
        let action_pub_key_path = tempdir.path().join("action_token_ed25519.pub.pem");
        let db_path = tempdir.path().join("signer.db");

        write_host_vault(&host_vault_dir, "local", "correct horse battery", &local_keys)?;
        write_peers_json(&peers_path, &peer_keys)?;
        write_public_key_pem(&action_pub_key_path)?;

        let cfg = SignerConfig {
            local_id: "local".to_string(),
            signer_role: SignerRole::Arbiter,
            sandbox_id: "sbx-local".to_string(),
            wallet_id: "wallet-local".to_string(),
            nettype: "stagenet".to_string(),
            peers_path,
            host_vault_dir,
            host_vault_passphrase: "correct horse battery".to_string(),
            runtime_trust_bundle_path: None,
            db_path: db_path.clone(),
            mailbox_url: mailbox_url.clone(),
            mailbox_push_token: Some("push-token-123456".to_string()),
            mailbox_pull_token: Some("pull-token-123456".to_string()),
            mailbox_ack_token: Some("ack-token-123456".to_string()),
            mailbox_admin_token: None,
            worker_service_token: Some("service-token-123456".to_string()),
            tor_socks5h: None,
            mailbox_retry_attempts: 3,
            mailbox_retry_backoff_ms: 50,
            allow_remote_wallet_rpc: false,
            production_hardening: false,
            wallet_rpc: WalletRpcConfig {
                endpoint: wallet_url,
                wallet_name: "wallet".to_string(),
                wallet_password: "pass".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            snapshot_quorum: 1,
            pull_max: 10,
            pull_wait_ms: 50,
            poll_interval_ms: 25,
            default_ttl_secs: 300,
            max_txset_hex_len: 2048,
            action_token: Some(ActionTokenConfig {
                required: true,
                issuer: "nxms-auth".to_string(),
                audience: Some("sandbox:sbx-local".to_string()),
                algorithm: "EDDSA".to_string(),
                public_key_pem_path: action_pub_key_path,
                clock_skew_secs: 5,
                max_ttl_secs: 120,
                verify_rate_limit_max_attempts: 8,
                verify_rate_limit_window_secs: 60,
                verify_rate_limit_max_keys: 4096,
            }),
            wallet_provision: None,
        };

        let agent = Arc::new(SignerAgent::from_config(cfg.clone()).await?);
        let db = SignerDb::new(db_path);

        Ok(Self {
            _tempdir: tempdir,
            agent,
            cfg,
            db,
            local_keys,
            peer_keys,
            ag01_keys,
            ag02_keys,
            mailbox_url,
            wallet_state,
        })
    }

    pub async fn seed_active_snapshot(&self, escrow_id_hex: &str) -> Result<ContractSnapshot> {
        let now = now_ms();
        let snapshot = ContractSnapshot {
            app_proto: ESCROW_APP_PROTO_V1.to_string(),
            escrow_id_hex: escrow_id_hex.to_string(),
            asset: Asset::Xmr,
            buyer_id: "buyer".to_string(),
            seller_id: "seller".to_string(),
            arbiter_id: "local".to_string(),
            release_policy: PayoutPolicy {
                allowed_recipients: vec![RecipientRule {
                    address: "release_addr".to_string(),
                    amount: AmountRule::Exact { amount: 100 },
                    required: true,
                }],
                allow_split_tx: false,
                allow_dummy_outputs: false,
            },
            refund_policy: PayoutPolicy {
                allowed_recipients: vec![RecipientRule {
                    address: "refund_addr".to_string(),
                    amount: AmountRule::Exact { amount: 100 },
                    required: true,
                }],
                allow_split_tx: false,
                allow_dummy_outputs: false,
            },
            fee_cap_atomic: 10,
            require_unlock_time_zero: true,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        let hash = canonical_hash_hex(&snapshot)?;
        self.db
            .put_snapshot_pending(
                &snapshot.escrow_id_hex,
                &hash,
                &serde_json::to_string(&snapshot)?,
            )
            .await?;
        self.db
            .put_snapshot_signature(&SnapshotSigRow {
                signer_id: "sig1".to_string(),
                sig_pk_b64: "x".to_string(),
                sig_b64: "y".to_string(),
                hash_hex: hash.clone(),
                alg: "Falcon-1024-CT".to_string(),
                created_at_unix_ms: now,
            })
            .await?;
        self.db.activate_snapshot(&hash, 1).await?;
        Ok(snapshot)
    }

    pub fn spawn_agent(&self) -> tokio::task::JoinHandle<Result<()>> {
        let agent = Arc::clone(&self.agent);
        tokio::spawn(async move { agent.run().await })
    }

    pub async fn push_sign_request(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        seq: u64,
    ) -> Result<()> {
        let ingress_client = MailboxClient::builder(&self.mailbox_url)?
            .push_token("push-token-123456")
            .build()?;
        let req_env = build_tx_sign_req_envelope(
            &self.local_keys,
            &self.peer_keys,
            escrow_id_hex,
            snapshot_hash_hex,
            seq,
        )
        .await?;
        ingress_client.push(&req_env, Some(60)).await?;
        Ok(())
    }

    pub async fn push_sign_request_with_admission(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        seq: u64,
        escrow_admission_artifact: EscrowAdmissionArtifact,
    ) -> Result<()> {
        let ingress_client = MailboxClient::builder(&self.mailbox_url)?
            .push_token("push-token-123456")
            .build()?;
        let req_env = build_tx_sign_req_envelope_with_admission(
            &self.local_keys,
            &self.peer_keys,
            escrow_id_hex,
            snapshot_hash_hex,
            seq,
            Some(escrow_admission_artifact),
        )
        .await?;
        ingress_client.push(&req_env, Some(60)).await?;
        Ok(())
    }

    pub async fn wait_for_pending_id(&self) -> Result<i64> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let pending = self.db.list_pending().await?;
            if pending.len() == 1 {
                return Ok(pending[0].id);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow!("timed out waiting for signer pending row"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub fn build_sign_action_token(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
    ) -> Result<String> {
        self.build_sign_action_token_with_trust_epoch(
            escrow_id_hex,
            snapshot_hash_hex,
            txset_hash_hex,
            jti,
            None,
        )
    }

    pub fn build_sign_action_token_with_trust_epoch(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
        runtime_trust_epoch: Option<&str>,
    ) -> Result<String> {
        self.build_sign_action_token_with_runtime(
            escrow_id_hex,
            snapshot_hash_hex,
            txset_hash_hex,
            jti,
            runtime_trust_epoch,
            None,
        )
    }

    pub fn build_sign_action_token_with_runtime(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
        runtime_trust_epoch: Option<&str>,
        escrow_admission_hash: Option<&str>,
    ) -> Result<String> {
        let now = unix_now_secs();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: format!("sandbox:{}", self.cfg.sandbox_id),
            sub: "arbiter_operator".to_string(),
            scope: "sign_multisig".to_string(),
            op: "sign_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_first".to_string(),
            escrow_id: escrow_id_hex.to_string(),
            wallet_id: self.cfg.wallet_id.clone(),
            sandbox_id: self.cfg.sandbox_id.clone(),
            txset_hash: txset_hash_hex.to_string(),
            snapshot_hash: snapshot_hash_hex.to_string(),
            nettype: self.cfg.nettype.clone(),
            runtime_trust_epoch: runtime_trust_epoch.map(str::to_string),
            escrow_admission_hash: escrow_admission_hash.map(str::to_string),
            iat: now,
            nbf: now,
            exp: now + 120,
            jti: jti.to_string(),
            proof_arbiter_jti: None,
            proof_seller_jti: None,
            proof_arbiter_req_id: None,
            proof_seller_req_id: None,
        };
        encode_action_claims(&claims)
    }

    pub fn build_submit_action_token(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
        proof_arbiter_jti: &str,
        proof_seller_jti: &str,
    ) -> Result<String> {
        self.build_submit_action_token_with_trust_epoch(
            escrow_id_hex,
            snapshot_hash_hex,
            txset_hash_hex,
            jti,
            proof_arbiter_jti,
            proof_seller_jti,
            None,
        )
    }

    pub fn build_submit_action_token_with_trust_epoch(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
        proof_arbiter_jti: &str,
        proof_seller_jti: &str,
        runtime_trust_epoch: Option<&str>,
    ) -> Result<String> {
        self.build_submit_action_token_with_runtime(
            escrow_id_hex,
            snapshot_hash_hex,
            txset_hash_hex,
            jti,
            proof_arbiter_jti,
            proof_seller_jti,
            runtime_trust_epoch,
            None,
        )
    }

    pub fn build_submit_action_token_with_runtime(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        txset_hash_hex: &str,
        jti: &str,
        proof_arbiter_jti: &str,
        proof_seller_jti: &str,
        runtime_trust_epoch: Option<&str>,
        escrow_admission_hash: Option<&str>,
    ) -> Result<String> {
        let now = unix_now_secs();
        let claims = ActionClaims {
            iss: "nxms-auth".to_string(),
            aud: format!("sandbox:{}", self.cfg.sandbox_id),
            sub: "arbiter_operator".to_string(),
            scope: "submit_multisig".to_string(),
            op: "submit_multisig".to_string(),
            role: "arbiter".to_string(),
            sign_round: "arbiter_submit".to_string(),
            escrow_id: escrow_id_hex.to_string(),
            wallet_id: self.cfg.wallet_id.clone(),
            sandbox_id: self.cfg.sandbox_id.clone(),
            txset_hash: txset_hash_hex.to_string(),
            snapshot_hash: snapshot_hash_hex.to_string(),
            nettype: self.cfg.nettype.clone(),
            runtime_trust_epoch: runtime_trust_epoch.map(str::to_string),
            escrow_admission_hash: escrow_admission_hash.map(str::to_string),
            iat: now,
            nbf: now,
            exp: now + 120,
            jti: jti.to_string(),
            proof_arbiter_jti: Some(proof_arbiter_jti.to_string()),
            proof_seller_jti: Some(proof_seller_jti.to_string()),
            proof_arbiter_req_id: Some(sign_req_id(
                escrow_id_hex,
                "sign_multisig",
                "arbiter_first",
                txset_hash_hex,
            )),
            proof_seller_req_id: Some(sign_req_id(
                escrow_id_hex,
                "sign_multisig",
                "seller_second",
                txset_hash_hex,
            )),
        };
        encode_action_claims(&claims)
    }

    pub fn peer_client(&self) -> Result<MailboxClient> {
        MailboxClient::builder(&self.mailbox_url)?
            .pull_token("peer1-pull-token-123456")
            .ack_token("peer1-ack-token-123456")
            .admin_token("admin-token-123456")
            .build()
    }

    pub fn decode_envelope_body(&self, env: &NxmsEnvelope) -> Result<EscrowBody> {
        decode_envelope_body(env, &self.local_keys, &self.peer_keys)
    }

    pub fn build_escrow_admission_artifact(
        &self,
        escrow_id_hex: &str,
        snapshot_hash_hex: &str,
        action: EscrowAction,
        runtime_trust_epoch: &str,
    ) -> Result<EscrowAdmissionArtifact> {
        let now = now_ms();
        let mut artifact = EscrowAdmissionArtifact::new(
            escrow_id_hex,
            snapshot_hash_hex,
            action,
            runtime_trust_epoch,
            now,
        );
        artifact.sign_with_local_keys("ag01", "ag-01", &self.ag01_keys, now)?;
        artifact.sign_with_local_keys("ag02", "ag-02", &self.ag02_keys, now)?;
        Ok(artifact)
    }

    pub fn wallet_calls(&self) -> Vec<String> {
        self.wallet_state
            .calls
            .lock()
            .expect("wallet calls lock")
            .clone()
    }
}

pub async fn stop_agent_task(task: tokio::task::JoinHandle<Result<()>>) {
    task.abort();
    let _ = task.await;
}

pub fn txset_sha256_hex(tx_data_hex: &str) -> Result<String> {
    let tx_data = hex::decode(tx_data_hex).context("decode tx_data_hex")?;
    Ok(hex::encode(Sha256::digest(tx_data)))
}

pub fn policy_hash_hex(snapshot: &ContractSnapshot) -> Result<String> {
    canonical_policy_hash_sha256_hex(snapshot)
}

pub fn write_action_token_private_key_pem(path: &Path) -> Result<()> {
    std::fs::write(path, ED25519_PRIVATE_PEM)
        .with_context(|| format!("write private key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }
    Ok(())
}

async fn wallet_rpc_handler(
    State(state): State<Arc<WalletMockState>>,
    Json(req): Json<Value>,
) -> impl IntoResponse {
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    state
        .calls
        .lock()
        .expect("wallet calls lock")
        .push(method.clone());

    let body = match method.as_str() {
        "close_wallet" | "open_wallet" => json!({ "jsonrpc":"2.0", "id":"0", "result": {} }),
        "is_multisig" => json!({
            "jsonrpc":"2.0",
            "id":"0",
            "result": {
                "multisig": true,
                "ready": true,
                "threshold": 2,
                "total": 3
            }
        }),
        "describe_transfer" => json!({
            "jsonrpc":"2.0",
            "id":"0",
            "result": {
                "desc": [{
                    "recipients": [{"address": "release_addr", "amount": 100}],
                    "fee": 10,
                    "unlock_time": 0,
                    "dummy_outputs": 0
                }]
            }
        }),
        "sign_multisig" => json!({
            "jsonrpc":"2.0",
            "id":"0",
            "result": {
                "tx_data_hex": "aa11",
                "tx_hash_list": ["abcd"]
            }
        }),
        "submit_multisig" => json!({
            "jsonrpc":"2.0",
            "id":"0",
            "result": {
                "tx_hash_list": ["submithash"]
            }
        }),
        other => json!({
            "jsonrpc":"2.0",
            "id":"0",
            "error": {
                "code": -1,
                "message": format!("unsupported test method: {other}")
            }
        }),
    };

    Json(body)
}

async fn spawn_http_server(router: Router) -> Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind test listener")?;
    let addr = listener.local_addr().context("test listener addr")?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(format!("http://{addr}"))
}

async fn spawn_real_mailbox_server(tempdir: &TempDir) -> Result<String> {
    let db = RealMailboxDb::new(tempdir.path().join("mailbox.db"));
    db.init()
        .await
        .map_err(|err| anyhow!("mailbox db init: {err}"))?;
    let state = MailboxAppState::new(
        db,
        MailboxApiConfig {
            push_token: Some("push-token-123456".to_string()),
            pull_tokens: std::collections::HashMap::from([
                ("local".to_string(), "pull-token-123456".to_string()),
                ("peer1".to_string(), "peer1-pull-token-123456".to_string()),
            ]),
            ack_tokens: std::collections::HashMap::from([
                ("local".to_string(), "ack-token-123456".to_string()),
                ("peer1".to_string(), "peer1-ack-token-123456".to_string()),
            ]),
            admin_token: Some("admin-token-123456".to_string()),
            max_body_bytes: 1024 * 1024,
            default_ttl_secs: 60,
            max_ttl_secs: 600,
            lease_secs: 30,
            max_wait_ms: 1000,
            limits: MailboxDbLimits {
                max_messages_per_inbox: 100,
                max_bytes_per_inbox: 1024 * 1024,
                max_rows_global: 1000,
            },
            rate_limit_ip_per_min: 1000,
            rate_limit_to_per_min: 1000,
        },
    );
    let app = build_mailbox_app(state, 1024 * 1024);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind mailbox listener")?;
    let addr = listener.local_addr().context("mailbox listener addr")?;
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    Ok(format!("http://{addr}"))
}

fn write_host_vault(dir: &Path, local_id: &str, passphrase: &str, keys: &Keys) -> Result<()> {
    HostVault::store(dir, passphrase, local_id, keys)
        .with_context(|| format!("write host vault {}", dir.display()))
}

fn write_peers_json(path: &Path, peer_keys: &Keys) -> Result<()> {
    let peerbook = PeerBook {
        peers: vec![Peer {
            id: "peer1".to_string(),
            host: "peer1.onion".to_string(),
            port: 80,
            kem_pk_b64: peer_keys.kem_pk_b64.clone(),
            sig_pk_b64: peer_keys.sig_pk_b64.clone(),
        }],
    };
    std::fs::write(path, serde_json::to_vec_pretty(&peerbook)?)
        .with_context(|| format!("write peers json {}", path.display()))
}

fn write_public_key_pem(path: &Path) -> Result<()> {
    std::fs::write(path, ED25519_PUBLIC_PEM)
        .with_context(|| format!("write public key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn encode_action_claims(claims: &ActionClaims) -> Result<String> {
    let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes())?;
    Ok(encode(&Header::new(Algorithm::EdDSA), claims, &key)?)
}

pub fn write_runtime_trust_bundle(
    path: &Path,
    local_id: &str,
    local_keys: &Keys,
    peer_id: &str,
    peer_keys: &Keys,
    ag01_keys: &Keys,
    ag02_keys: &Keys,
    action_token_public_key_path: &Path,
    trust_epoch: &str,
) -> Result<()> {
    let action_token_public_key = std::fs::read_to_string(action_token_public_key_path)
        .with_context(|| format!("read {}", action_token_public_key_path.display()))?;
    let bundle = RuntimeTrustBundle {
        schema: "nxms-runtime-trust-bundle/v1".to_string(),
        trust_epoch: trust_epoch.to_string(),
        peers: vec![
            RuntimeTrustPeer {
                id: local_id.to_string(),
                role: "signer".to_string(),
                host: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
                    .to_string(),
                port: 443,
                kem_pk_b64: local_keys.kem_pk_b64.clone(),
                sig_pk_b64: local_keys.sig_pk_b64.clone(),
            },
            RuntimeTrustPeer {
                id: peer_id.to_string(),
                role: "orchestrator".to_string(),
                host: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
                    .to_string(),
                port: 443,
                kem_pk_b64: peer_keys.kem_pk_b64.clone(),
                sig_pk_b64: peer_keys.sig_pk_b64.clone(),
            },
            RuntimeTrustPeer {
                id: "ag01".to_string(),
                role: "ag-01".to_string(),
                host: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion"
                    .to_string(),
                port: 443,
                kem_pk_b64: ag01_keys.kem_pk_b64.clone(),
                sig_pk_b64: ag01_keys.sig_pk_b64.clone(),
            },
            RuntimeTrustPeer {
                id: "ag02".to_string(),
                role: "ag-02".to_string(),
                host: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion"
                    .to_string(),
                port: 443,
                kem_pk_b64: ag02_keys.kem_pk_b64.clone(),
                sig_pk_b64: ag02_keys.sig_pk_b64.clone(),
            },
        ],
        action_token: RuntimeActionTokenIssuer {
            issuer: "nxms-auth".to_string(),
            algorithm: "EDDSA".to_string(),
            public_key_pem: action_token_public_key,
        },
    };
    std::fs::write(path, serde_json::to_vec_pretty(&bundle)?)
        .with_context(|| format!("write runtime trust bundle {}", path.display()))?;
    Ok(())
}

fn decode_escrow_id_hex(escrow_id_hex: &str) -> Result<[u8; 16]> {
    let raw = hex::decode(escrow_id_hex).context("decode escrow id hex")?;
    raw.try_into()
        .map_err(|_| anyhow!("escrow id must decode to exactly 16 bytes"))
}

async fn build_tx_sign_req_envelope(
    local_keys: &Keys,
    peer_keys: &Keys,
    escrow_id_hex: &str,
    snapshot_hash_hex: &str,
    seq: u64,
) -> Result<NxmsEnvelope> {
    build_tx_sign_req_envelope_with_admission(
        local_keys,
        peer_keys,
        escrow_id_hex,
        snapshot_hash_hex,
        seq,
        None,
    )
    .await
}

async fn build_tx_sign_req_envelope_with_admission(
    local_keys: &Keys,
    peer_keys: &Keys,
    escrow_id_hex: &str,
    snapshot_hash_hex: &str,
    seq: u64,
    escrow_admission_artifact: Option<EscrowAdmissionArtifact>,
) -> Result<NxmsEnvelope> {
    let escrow_id_raw = decode_escrow_id_hex(escrow_id_hex)?;
    let body = EscrowBody::TxSignReq(TxSignReqBody {
        escrow_id_hex: escrow_id_hex.to_string(),
        action: EscrowAction::Release,
        multisig_txset_hex: "aa11".to_string(),
        snapshot_hash_hex: snapshot_hash_hex.to_string(),
        escrow_admission_artifact,
        human_hint: Some("approve release".to_string()),
    });
    let payload = NxmsPayload {
        app_proto: ESCROW_APP_PROTO_V1.to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: escrow_id_hex.to_string(),
        from: "peer1".to_string(),
        to: "local".to_string(),
        seq,
        data: serde_json::to_string(&body)?,
    };
    let plain = serde_json::to_vec(&payload)?;
    let local_kem_pk = local_keys.kem_pk()?;
    let peer_sig_sk = peer_keys.sig_sk_zeroizing()?;
    let sealed = encrypt(
        "peer1",
        "local",
        msg_type_key(&MsgType::TxSignReq),
        &escrow_id_raw,
        seq,
        &local_kem_pk,
        peer_sig_sk.as_slice(),
        &plain,
    )?;

    Ok(NxmsEnvelope {
        proto: "NXMS/1".to_string(),
        kem_id: suite_kem_id().to_string(),
        sig_id: suite_sig_id().to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: escrow_id_hex.to_string(),
        from: "peer1".to_string(),
        to: "local".to_string(),
        seq,
        kem_ct_b64: sealed.kem_ct_b64,
        nonce_b64: sealed.nonce_b64,
        ciphertext_b64: sealed.ciphertext_b64,
        tag_b64: sealed.tag_b64,
        sig_b64: sealed.sig_b64,
    })
}

fn decode_envelope_body(
    env: &NxmsEnvelope,
    local_keys: &Keys,
    peer_keys: &Keys,
) -> Result<EscrowBody> {
    let escrow_id_raw = decode_escrow_id_hex(&env.escrow_id_hex)?;
    let sealed = SealedPacket {
        kem_ct_b64: env.kem_ct_b64.clone(),
        nonce_b64: env.nonce_b64.clone(),
        ciphertext_b64: env.ciphertext_b64.clone(),
        tag_b64: env.tag_b64.clone(),
        sig_b64: env.sig_b64.clone(),
    };
    let peer_kem_sk = peer_keys.kem_sk_zeroizing()?;
    let local_sig_pk = local_keys.sig_pk()?;
    let plain = decrypt(
        &env.from,
        &env.to,
        msg_type_key(&env.msg_type),
        &escrow_id_raw,
        env.seq,
        &sealed,
        peer_kem_sk.as_slice(),
        &local_sig_pk,
    )?;
    let payload: NxmsPayload = serde_json::from_slice(&plain)?;
    Ok(serde_json::from_str(&payload.data)?)
}
