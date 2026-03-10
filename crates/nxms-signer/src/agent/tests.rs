use super::*;
use crate::action_token::{ActionClaims, ActionTokenVerifier, sign_req_id};
use crate::config::{ActionTokenConfig, SignerRole, WalletRpcConfig};
use crate::db::SnapshotSigRow;
use crate::snapshot::{
    AmountRule, Asset, ContractSnapshot, PayoutPolicy, RecipientRule, canonical_hash_hex,
    canonical_policy_hash_sha256_hex,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use nxms_mailbox::{
    AppState as MailboxAppState, api::ApiConfig as MailboxApiConfig,
    build_app as build_mailbox_app,
    db::{MailboxLimits as MailboxDbLimits, SqliteMailboxDb as RealMailboxDb},
};
use nxms_transport::crypto::decrypt;
use nxms_transport::peers::{Peer, PeerBook};
use nxms_transport::wire::TxSignReqBody;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCBxRIEv7DU1o/rRG+beqeRLVa2kL9RAArTq6vRp7D0\n-----END PRIVATE KEY-----\n";
const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAD7TxzeCSPJhJljqWs/fABRUaUBlTkJP8O1v31Z64F/I=\n-----END PUBLIC KEY-----\n";

#[test]
fn non_retryable_process_error_ack_policy_marks_validation_failures() {
    let validation = anyhow::anyhow!("invalid action token: invalid signature");
    assert!(should_ack_non_retryable_process_error(&validation));

    let transient = anyhow::anyhow!("wallet-rpc transport failed: timed out");
    assert!(!should_ack_non_retryable_process_error(&transient));
}

#[derive(Default)]
struct MailboxMockState {
    mailbox_pushes: Mutex<Vec<Value>>,
    fail_push: Mutex<bool>,
}

#[derive(Clone)]
struct ConsumeCheck {
    db_path: PathBuf,
    jti: String,
}

struct WalletMockState {
    calls: Mutex<Vec<String>>,
    describe_address: Mutex<String>,
    describe_amount: Mutex<u64>,
    describe_fee: Mutex<u64>,
    describe_unlock_time: Mutex<u64>,
    describe_dummy_outputs: Mutex<u64>,
    sign_error_message: Mutex<Option<String>>,
    submit_error_message: Mutex<Option<String>>,
    consume_check: Mutex<Option<ConsumeCheck>>,
    consumed_seen_on_sign: Mutex<Option<bool>>,
}

impl Default for WalletMockState {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            describe_address: Mutex::new("release_addr".to_string()),
            describe_amount: Mutex::new(100),
            describe_fee: Mutex::new(10),
            describe_unlock_time: Mutex::new(0),
            describe_dummy_outputs: Mutex::new(0),
            sign_error_message: Mutex::new(None),
            submit_error_message: Mutex::new(None),
            consume_check: Mutex::new(None),
            consumed_seen_on_sign: Mutex::new(None),
        }
    }
}

struct TokenFixture {
    key_path: PathBuf,
    encoding_key: EncodingKey,
}

struct TestHarness {
    agent: SignerAgent,
    mailbox_state: Arc<MailboxMockState>,
    wallet_state: Arc<WalletMockState>,
    local_keys: Keys,
    peer_keys: Keys,
    db_path: PathBuf,
    mailbox_url: String,
    wallet_url: String,
}

async fn mailbox_push_handler(
    State(state): State<Arc<MailboxMockState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if *state.fail_push.lock().expect("fail_push lock") {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail":"forced push failure"})),
        )
            .into_response();
    }
    state.mailbox_pushes.lock().expect("push lock").push(body);
    (StatusCode::OK, Json(json!({ "ok": true, "dedup": false }))).into_response()
}

async fn wallet_rpc_handler(
    State(state): State<Arc<WalletMockState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    state.calls.lock().expect("calls lock").push(method.clone());

    match method.as_str() {
        "close_wallet" | "open_wallet" => Json(json!({ "jsonrpc":"2.0", "id":"0", "result": {} })),
        "describe_transfer" => {
            let address = state
                .describe_address
                .lock()
                .expect("describe_address lock")
                .clone();
            let amount = *state.describe_amount.lock().expect("describe_amount lock");
            let fee = *state.describe_fee.lock().expect("describe_fee lock");
            let unlock_time = *state
                .describe_unlock_time
                .lock()
                .expect("describe_unlock_time lock");
            let dummy_outputs = *state
                .describe_dummy_outputs
                .lock()
                .expect("describe_dummy_outputs lock");
            Json(json!({
                "jsonrpc":"2.0",
                "id":"0",
                "result": {
                    "desc": [{
                        "recipients": [{"address": address, "amount": amount}],
                        "fee": fee,
                        "unlock_time": unlock_time,
                        "dummy_outputs": dummy_outputs
                    }]
                }
            }))
        }
        "sign_multisig" => {
            if let Some(check) = state
                .consume_check
                .lock()
                .expect("consume_check lock")
                .clone()
            {
                let conn = Connection::open(&check.db_path).expect("open signer db");
                let found: Option<i64> = conn
                    .query_row(
                        "SELECT 1 FROM consumed_action_jti WHERE jti=?1 LIMIT 1",
                        params![check.jti],
                        |row| row.get(0),
                    )
                    .optional()
                    .expect("query consumed jti");
                *state
                    .consumed_seen_on_sign
                    .lock()
                    .expect("consumed_seen lock") = Some(found.is_some());
            }

            if let Some(msg) = state
                .sign_error_message
                .lock()
                .expect("sign_error lock")
                .clone()
            {
                return Json(json!({
                    "jsonrpc":"2.0",
                    "id":"0",
                    "error": {
                        "code": -42,
                        "message": msg
                    }
                }));
            }
            Json(json!({
                "jsonrpc":"2.0",
                "id":"0",
                "result": {
                    "tx_data_hex": "aa11",
                    "tx_hash_list": ["abcd"]
                }
            }))
        }
        "submit_multisig" => {
            if let Some(msg) = state
                .submit_error_message
                .lock()
                .expect("submit_error lock")
                .clone()
            {
                return Json(json!({
                    "jsonrpc":"2.0",
                    "id":"0",
                    "error": {
                        "code": -43,
                        "message": msg
                    }
                }));
            }
            Json(json!({
                "jsonrpc":"2.0",
                "id":"0",
                "result": {
                    "tx_hash_list": ["submithash"]
                }
            }))
        }
        _ => Json(json!({ "jsonrpc":"2.0", "id":"0", "result": {} })),
    }
}

async fn spawn_server(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{}", addr)
}

async fn spawn_real_mailbox_server(label: &str) -> (String, PathBuf) {
    let db_path = unique_db_path(&format!("real_mailbox_{label}"));
    let db = RealMailboxDb::new(db_path.clone());
    db.init().await.expect("real mailbox db init");
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
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (format!("http://{}", addr), db_path)
}

fn unique_db_path(label: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "nxms_signer_agent_test_{label}_{}_{}.db",
        std::process::id(),
        ts
    ))
}

fn unique_pem_path(label: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "nxms_signer_action_token_{label}_{}_{}.pem",
        std::process::id(),
        ts
    ))
}

async fn seed_active_snapshot(db: &SignerDb, escrow_id_hex: &str) -> ContractSnapshot {
    let now = now_ms();
    let snapshot = ContractSnapshot {
        app_proto: "ESCROW/1".to_string(),
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
    let hash = canonical_hash_hex(&snapshot).expect("hash");
    db.put_snapshot_pending(
        &snapshot.escrow_id_hex,
        &hash,
        &serde_json::to_string(&snapshot).expect("snapshot json"),
    )
    .await
    .expect("put snapshot");
    db.put_snapshot_signature(&SnapshotSigRow {
        signer_id: "sig1".to_string(),
        sig_pk_b64: "x".to_string(),
        sig_b64: "y".to_string(),
        hash_hex: hash.clone(),
        alg: "Falcon-1024-CT".to_string(),
        created_at_unix_ms: now,
    })
    .await
    .expect("put signature");
    db.activate_snapshot(&hash, 1).await.expect("activate");
    snapshot
}

async fn make_agent(
    mailbox_url: String,
    wallet_url: String,
    db_path: PathBuf,
    local_keys: Keys,
    peer_keys: Keys,
) -> SignerAgent {
    let db = SignerDb::new(db_path);
    db.init().await.expect("db init");

    let cfg = SignerConfig {
        local_id: "local".to_string(),
        signer_role: SignerRole::Arbiter,
        sandbox_id: "sbx-local".to_string(),
        wallet_id: "wallet-local".to_string(),
        nettype: "stagenet".to_string(),
        peers_path: PathBuf::new(),
        keys_path: PathBuf::new(),
        db_path: PathBuf::new(),
        mailbox_url: mailbox_url.clone(),
        mailbox_push_token: Some("push-token-123456".to_string()),
        mailbox_pull_token: Some("pull-token-123456".to_string()),
        mailbox_ack_token: Some("ack-token-123456".to_string()),
        mailbox_admin_token: None,
        worker_service_token: Some("service-token-123456".to_string()),
        tor_socks5h: None,
        mailbox_retry_attempts: 3,
        mailbox_retry_backoff_ms: 250,
        allow_remote_wallet_rpc: false,
        production_hardening: false,
        wallet_rpc: WalletRpcConfig {
            endpoint: "http://127.0.0.1".to_string(),
            wallet_name: "wallet".to_string(),
            wallet_password: "pass".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
        },
        snapshot_quorum: 1,
        pull_max: 10,
        pull_wait_ms: 0,
        poll_interval_ms: 100,
        default_ttl_secs: 300,
        max_txset_hex_len: 2048,
        action_token: None,
        wallet_provision: None,
    };

    let mailbox = MailboxClient::builder(&mailbox_url)
        .expect("mailbox builder")
        .push_token(
            cfg.mailbox_push_token
                .clone()
                .expect("push token configured"),
        )
        .pull_token(
            cfg.mailbox_pull_token
                .clone()
                .expect("pull token configured"),
        )
        .ack_token(
            cfg.mailbox_ack_token
                .clone()
                .expect("ack token configured"),
        )
        .build()
        .expect("mailbox client");
    let wallet = WalletRpcClient::new(
        wallet_url,
        "wallet".to_string(),
        "pass".to_string(),
        "user".to_string(),
        "pass".to_string(),
    )
    .expect("wallet client");

    SignerAgent {
        cfg,
        db,
        peers: PeerBook {
            peers: vec![Peer {
                id: "peer1".to_string(),
                host: "peer1.onion".to_string(),
                port: 80,
                kem_pk_b64: peer_keys.kem_pk_b64.clone(),
                sig_pk_b64: peer_keys.sig_pk_b64.clone(),
            }],
        },
        keys: local_keys,
        mailbox,
        wallet,
        action_token_verifier: None,
    }
}

async fn build_tx_sign_req_envelope(
    local_keys: &Keys,
    peer_keys: &Keys,
    escrow_id_hex: &str,
    snapshot_hash_hex: &str,
    seq: u64,
) -> NxmsEnvelope {
    build_tx_sign_req_envelope_with_txset(
        local_keys,
        peer_keys,
        escrow_id_hex,
        snapshot_hash_hex,
        seq,
        "aa11",
    )
    .await
}

async fn build_tx_sign_req_envelope_with_txset(
    local_keys: &Keys,
    peer_keys: &Keys,
    escrow_id_hex: &str,
    snapshot_hash_hex: &str,
    seq: u64,
    multisig_txset_hex: &str,
) -> NxmsEnvelope {
    let escrow_id_raw = decode_escrow_id_hex(escrow_id_hex).expect("escrow id");
    let body = EscrowBody::TxSignReq(TxSignReqBody {
        escrow_id_hex: escrow_id_hex.to_string(),
        action: nxms_transport::wire::EscrowAction::Release,
        multisig_txset_hex: multisig_txset_hex.to_string(),
        snapshot_hash_hex: snapshot_hash_hex.to_string(),
        human_hint: Some("approve release".to_string()),
    });
    let payload = NxmsPayload {
        app_proto: ESCROW_APP_PROTO_V1.to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: escrow_id_hex.to_string(),
        from: "peer1".to_string(),
        to: "local".to_string(),
        seq,
        data: serde_json::to_string(&body).expect("body json"),
    };
    let plain = serde_json::to_vec(&payload).expect("payload json");

    let local_kem_pk = local_keys.kem_pk().expect("local kem pk");
    let peer_sig_sk = peer_keys.sig_sk_zeroizing().expect("peer sig sk");
    let sealed = encrypt(
        "peer1",
        "local",
        msg_type_key(&MsgType::TxSignReq),
        &escrow_id_raw,
        seq,
        &local_kem_pk,
        peer_sig_sk.as_slice(),
        &plain,
    )
    .expect("encrypt");

    NxmsEnvelope {
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
    }
}

async fn setup_harness(label: &str) -> TestHarness {
    let mailbox_state = Arc::new(MailboxMockState::default());
    let mailbox_url = spawn_server(
        Router::new()
            .route("/v1/push", post(mailbox_push_handler))
            .with_state(mailbox_state.clone()),
    )
    .await;

    let wallet_state = Arc::new(WalletMockState::default());
    let wallet_url = spawn_server(
        Router::new()
            .route("/json_rpc", post(wallet_rpc_handler))
            .with_state(wallet_state.clone()),
    )
    .await;

    let local_keys = Keys::generate().expect("local keys");
    let peer_keys = Keys::generate().expect("peer keys");
    let local_keys_for_agent: Keys = serde_json::from_slice(
        serde_json::to_vec(&local_keys)
            .expect("serialize local keys")
            .as_slice(),
    )
    .expect("deserialize local keys");
    let peer_keys_for_agent: Keys = serde_json::from_slice(
        serde_json::to_vec(&peer_keys)
            .expect("serialize peer keys")
            .as_slice(),
    )
    .expect("deserialize peer keys");
    let db_path = unique_db_path(label);
    let agent = make_agent(
        mailbox_url.clone(),
        wallet_url.clone(),
        db_path.clone(),
        local_keys_for_agent,
        peer_keys_for_agent,
    )
    .await;

    TestHarness {
        agent,
        mailbox_state,
        wallet_state,
        local_keys,
        peer_keys,
        db_path,
        mailbox_url,
        wallet_url,
    }
}

fn clone_keys(keys: &Keys) -> Keys {
    serde_json::from_slice(
        serde_json::to_vec(keys)
            .expect("serialize keys")
            .as_slice(),
    )
    .expect("deserialize keys")
}

fn remove_file_quiet(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

async fn enqueue_pending(
    agent: &SignerAgent,
    escrow_id_hex: &str,
    seq: u64,
    status: &str,
    snapshot_hash_hex: &str,
    txset_hash_hex: String,
) -> i64 {
    let now = now_ms();
    let pending = PendingTxSign {
        id: 0,
        escrow_id_hex: escrow_id_hex.to_string(),
        from_id: "peer1".to_string(),
        to_id: "local".to_string(),
        seq,
        action: "\"release\"".to_string(),
        snapshot_hash_hex: snapshot_hash_hex.to_string(),
        multisig_txset_hex: "aa11".to_string(),
        txset_hash_hex,
        describe_transfer_json: "{}".to_string(),
        status: status.to_string(),
        decision_reason: None,
        created_at_ms: now,
        updated_at_ms: now,
    };
    agent
        .db
        .enqueue_pending_tx(&pending)
        .await
        .expect("enqueue pending");
    let rows = agent.db.list_pending().await.expect("list pending");
    rows.iter()
        .find(|p| p.seq == seq)
        .expect("pending row id")
        .id
}

async fn get_pending(agent: &SignerAgent, id: i64) -> PendingTxSign {
    agent
        .db
        .get_pending(id)
        .await
        .expect("get pending")
        .expect("pending exists")
}

fn wallet_calls(state: &Arc<WalletMockState>) -> Vec<String> {
    state.calls.lock().expect("calls lock").clone()
}

fn wallet_call_count(state: &Arc<WalletMockState>, method: &str) -> usize {
    state
        .calls
        .lock()
        .expect("calls lock")
        .iter()
        .filter(|m| m.as_str() == method)
        .count()
}

fn clear_wallet_calls(state: &Arc<WalletMockState>) {
    state.calls.lock().expect("calls lock").clear();
}

fn mailbox_pushes(state: &Arc<MailboxMockState>) -> Vec<Value> {
    state.mailbox_pushes.lock().expect("push lock").clone()
}

fn install_action_token_verifier(
    agent: &mut SignerAgent,
    required: bool,
    label: &str,
) -> TokenFixture {
    let key_path = unique_pem_path(label);
    std::fs::write(&key_path, ED25519_PUBLIC_PEM).expect("write public key");

    let mut cfg = agent.cfg.clone();
    cfg.action_token = Some(ActionTokenConfig {
        required,
        issuer: "nxms-auth".to_string(),
        audience: Some(format!("sandbox:{}", cfg.sandbox_id)),
        algorithm: "EDDSA".to_string(),
        public_key_pem_path: key_path.clone(),
        clock_skew_secs: 5,
        max_ttl_secs: 120,
        verify_rate_limit_max_attempts: 8,
        verify_rate_limit_window_secs: 60,
        verify_rate_limit_max_keys: 4096,
    });
    let verifier = ActionTokenVerifier::from_signer_config(&cfg)
        .expect("build verifier")
        .expect("verifier enabled");
    agent.cfg = cfg;
    agent.action_token_verifier = Some(verifier);

    TokenFixture {
        key_path,
        encoding_key: EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes())
            .expect("encoding key"),
    }
}

fn build_sign_action_claims(
    agent: &SignerAgent,
    escrow_id_hex: &str,
    txset_hash_hex: &str,
    snapshot_hash_hex: &str,
    jti: &str,
) -> ActionClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ActionClaims {
        iss: "nxms-auth".to_string(),
        aud: format!("sandbox:{}", agent.cfg.sandbox_id),
        sub: "arbiter_operator".to_string(),
        scope: "sign_multisig".to_string(),
        op: "sign_multisig".to_string(),
        role: "arbiter".to_string(),
        sign_round: "arbiter_first".to_string(),
        escrow_id: escrow_id_hex.to_string(),
        wallet_id: agent.cfg.wallet_id.clone(),
        sandbox_id: agent.cfg.sandbox_id.clone(),
        txset_hash: txset_hash_hex.to_string(),
        snapshot_hash: snapshot_hash_hex.to_string(),
        nettype: agent.cfg.nettype.clone(),
        iat: now,
        nbf: now,
        exp: now + 120,
        jti: jti.to_string(),
        proof_arbiter_jti: None,
        proof_seller_jti: None,
        proof_arbiter_req_id: None,
        proof_seller_req_id: None,
    }
}

fn build_sign_action_token(
    agent: &SignerAgent,
    fixture: &TokenFixture,
    escrow_id_hex: &str,
    txset_hash_hex: &str,
    snapshot_hash_hex: &str,
    jti: &str,
) -> String {
    let claims =
        build_sign_action_claims(agent, escrow_id_hex, txset_hash_hex, snapshot_hash_hex, jti);
    encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode")
}

fn build_submit_action_token(
    agent: &SignerAgent,
    fixture: &TokenFixture,
    escrow_id_hex: &str,
    txset_hash_hex: &str,
    snapshot_hash_hex: &str,
    jti: &str,
    proof_arbiter_jti: &str,
    proof_arbiter_req_id: &str,
    proof_seller_jti: &str,
    proof_seller_req_id: &str,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let claims = ActionClaims {
        iss: "nxms-auth".to_string(),
        aud: format!("sandbox:{}", agent.cfg.sandbox_id),
        sub: "arbiter_operator".to_string(),
        scope: "submit_multisig".to_string(),
        op: "submit_multisig".to_string(),
        role: "arbiter".to_string(),
        sign_round: "arbiter_submit".to_string(),
        escrow_id: escrow_id_hex.to_string(),
        wallet_id: agent.cfg.wallet_id.clone(),
        sandbox_id: agent.cfg.sandbox_id.clone(),
        txset_hash: txset_hash_hex.to_string(),
        snapshot_hash: snapshot_hash_hex.to_string(),
        nettype: agent.cfg.nettype.clone(),
        iat: now,
        nbf: now,
        exp: now + 120,
        jti: jti.to_string(),
        proof_arbiter_jti: Some(proof_arbiter_jti.to_string()),
        proof_seller_jti: Some(proof_seller_jti.to_string()),
        proof_arbiter_req_id: Some(proof_arbiter_req_id.to_string()),
        proof_seller_req_id: Some(proof_seller_req_id.to_string()),
    };
    encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode")
}

fn consumed_jti_exists(db_path: &PathBuf, jti: &str) -> bool {
    let conn = Connection::open(db_path).expect("open db");
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM consumed_action_jti WHERE jti=?1 LIMIT 1",
            params![jti],
            |row| row.get(0),
        )
        .optional()
        .expect("query jti");
    found.is_some()
}

fn sign_request_status(db_path: &PathBuf, req_id: &str) -> Option<String> {
    let conn = Connection::open(db_path).expect("open db");
    conn.query_row(
        "SELECT status FROM sign_request_dedup WHERE req_id=?1",
        params![req_id],
        |row| row.get(0),
    )
    .optional()
    .expect("query sign_request status")
}

fn decode_push_body(push: &Value, local_keys: &Keys, peer_keys: &Keys) -> EscrowBody {
    let envelope_value = push
        .get("envelope")
        .cloned()
        .expect("push.envelope present");
    let envelope: NxmsEnvelope = serde_json::from_value(envelope_value).expect("envelope json");
    let escrow_id_raw = decode_escrow_id_hex(&envelope.escrow_id_hex).expect("escrow id");
    let sealed = SealedPacket {
        kem_ct_b64: envelope.kem_ct_b64.clone(),
        nonce_b64: envelope.nonce_b64.clone(),
        ciphertext_b64: envelope.ciphertext_b64.clone(),
        tag_b64: envelope.tag_b64.clone(),
        sig_b64: envelope.sig_b64.clone(),
    };
    let peer_kem_sk = peer_keys.kem_sk_zeroizing().expect("peer kem sk");
    let local_sig_pk = local_keys.sig_pk().expect("local sig pk");
    let plain = decrypt(
        &envelope.from,
        &envelope.to,
        msg_type_key(&envelope.msg_type),
        &escrow_id_raw,
        envelope.seq,
        &sealed,
        peer_kem_sk.as_slice(),
        &local_sig_pk,
    )
    .expect("decrypt pushed envelope");
    let payload: NxmsPayload = serde_json::from_slice(&plain).expect("payload json");
    serde_json::from_str(&payload.data).expect("payload body json")
}

fn push_envelope_seq(push: &Value) -> u64 {
    push.get("envelope")
        .and_then(|v| v.get("seq"))
        .and_then(Value::as_u64)
        .expect("push envelope seq")
}

#[test]
fn validate_tx_sign_req_rejects_invalid_snapshot_hash() {
    let payload = NxmsPayload {
        app_proto: ESCROW_APP_PROTO_V1.to_string(),
        msg_type: MsgType::TxSignReq,
        escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
        from: "peer1".to_string(),
        to: "local".to_string(),
        seq: 1,
        data: "{}".to_string(),
    };
    let req = TxSignReqBody {
        escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
        action: EscrowAction::Release,
        multisig_txset_hex: "aa11".to_string(),
        snapshot_hash_hex: "not_hex".to_string(),
        human_hint: None,
    };
    let err = validate_tx_sign_req(&payload, &req, 2048).expect_err("must reject");
    assert!(err.to_string().contains("snapshot_hash_hex"));
}

#[test]
fn normalize_hex_exact_accepts_and_normalizes_uppercase() {
    let value = normalize_hex_exact(
        "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
        64,
        "h",
    )
    .expect("normalized");
    assert_eq!(
        value,
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    );
}

#[test]
fn parse_pending_action_rejects_non_json() {
    let err = parse_pending_action("release").expect_err("must reject invalid JSON");
    assert!(err.to_string().contains("invalid stored action JSON"));
}

#[test]
fn validate_tx_data_hex_rejects_invalid_hex() {
    let err = validate_tx_data_hex("aa1", 2048).expect_err("odd length must fail");
    assert!(err.to_string().contains("even-length hex"));
}

#[test]
fn txset_sha256_hex_hashes_decoded_bytes_not_hex_text_representation() {
    use sha2::{Digest, Sha256};

    let lower = txset_sha256_hex("aa11").expect("lower hash");
    let upper = txset_sha256_hex("AA11").expect("upper hash");
    assert_eq!(lower, upper);

    let mut hasher = Sha256::new();
    hasher.update([0xaa_u8, 0x11_u8]);
    let expected = hex::encode(hasher.finalize());
    assert_eq!(lower, expected);
}

#[test]
fn resolve_wallet_cli_wallet_file_prefers_wallet_dir_for_relative_name() {
    let cfg = SignerConfig {
        local_id: "local".to_string(),
        signer_role: SignerRole::Arbiter,
        sandbox_id: "sbx-local".to_string(),
        wallet_id: "wallet-local".to_string(),
        nettype: "stagenet".to_string(),
        peers_path: PathBuf::from("/tmp/peers.json"),
        keys_path: PathBuf::from("/tmp/keys.json"),
        db_path: PathBuf::from("/tmp/signer.db"),
        mailbox_url: "http://mailbox.onion".to_string(),
        mailbox_push_token: Some("push-token-123456".to_string()),
        mailbox_pull_token: Some("pull-token-123456".to_string()),
        mailbox_ack_token: Some("ack-token-123456".to_string()),
        mailbox_admin_token: None,
        worker_service_token: Some("service-token-123456".to_string()),
        tor_socks5h: None,
        mailbox_retry_attempts: 3,
        mailbox_retry_backoff_ms: 250,
        allow_remote_wallet_rpc: false,
        production_hardening: false,
        wallet_rpc: WalletRpcConfig {
            endpoint: "http://127.0.0.1:18088".to_string(),
            wallet_name: "escrow_wallet".to_string(),
            wallet_password: "pw".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
        },
        snapshot_quorum: 1,
        pull_max: 10,
        pull_wait_ms: 0,
        poll_interval_ms: 100,
        default_ttl_secs: 60,
        max_txset_hex_len: 2048,
        action_token: None,
        wallet_provision: None,
    };
    let path = resolve_wallet_cli_wallet_file(&cfg, Some(&PathBuf::from("/var/lib/monero")));
    assert_eq!(path, PathBuf::from("/var/lib/monero/escrow_wallet"));
}

#[tokio::test]
async fn process_envelope_enqueues_pending_tx() {
    let h = setup_harness("enqueue_pending").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let env = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;

    h.agent
        .process_envelope(env)
        .await
        .expect("process envelope");
    let pending = h.agent.db.list_pending().await.expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, "pending");

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn smoke_process_then_approve_roundtrip() {
    let mut h = setup_harness("smoke_roundtrip").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "smoke-roundtrip");
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let env = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;

    h.agent
        .process_envelope(env)
        .await
        .expect("process envelope");
    let pending = h.agent.db.list_pending().await.expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, "pending");

    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &pending[0].txset_hash_hex,
        &snapshot_hash_for_token,
        "jti-smoke-roundtrip",
    );
    h.agent
        .approve_pending(pending[0].id, Some(&token))
        .await
        .expect("approve smoke path");

    let row = get_pending(&h.agent, pending[0].id).await;
    assert_eq!(row.status, "approved_sent");
    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    let body = decode_push_body(&pushes[0], &h.local_keys, &h.peer_keys);
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    assert_eq!(resp.signed_tx_data_hex.as_deref(), Some("aa11"));

    let audit = h.agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "rx_validated"));
    assert!(audit.iter().any(|e| e.event_kind == "pending_enqueued"));
    assert!(audit.iter().any(|e| e.event_kind == "decision_approved"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn process_envelope_rejects_snapshot_mismatch_before_describe_transfer() {
    let h = setup_harness("enqueue_pending_snapshot_mismatch").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let mismatched_snapshot_hash = "11".repeat(32);
    let env = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &mismatched_snapshot_hash,
        1,
    )
    .await;

    let err = h
        .agent
        .process_envelope(env)
        .await
        .expect_err("snapshot mismatch must reject");
    assert!(err.to_string().contains("snapshot_hash mismatch"));
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(
        h.agent
            .db
            .list_pending()
            .await
            .expect("list pending")
            .is_empty()
    );

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn process_envelope_rejects_out_of_order_seq_and_audits_replay() {
    let h = setup_harness("out_of_order_seq").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let env_seq_2 = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        2,
    )
    .await;
    let env_seq_1 = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;

    h.agent
        .process_envelope(env_seq_2)
        .await
        .expect("first higher seq accepted");
    let err = h
        .agent
        .process_envelope(env_seq_1)
        .await
        .expect_err("lower seq must be rejected");
    let err_text = err.to_string().to_ascii_lowercase();
    assert!(err_text.contains("out-of-order") || err_text.contains("replay"));

    let pending = h.agent.db.list_pending().await.expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].seq, 2);

    let audit = h.agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "rx_rejected_replay"));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn e2e_abuse_rejects_malformed_envelope_crypto_fields() {
    let h = setup_harness("abuse_malformed_envelope").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let mut env = build_tx_sign_req_envelope(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;
    env.ciphertext_b64 = "@@@not-base64@@@".to_string();

    let err = h
        .agent
        .process_envelope(env)
        .await
        .expect_err("malformed envelope must reject");
    let err_text = err.to_string().to_ascii_lowercase();
    assert!(
        err_text.contains("base64") || err_text.contains("decode") || err_text.contains("invalid")
    );
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(
        h.agent
            .db
            .list_pending()
            .await
            .expect("list pending")
            .is_empty()
    );

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn e2e_abuse_rejects_oversized_txset_before_wallet_call() {
    let mut h = setup_harness("abuse_oversized_txset").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    h.agent.cfg.max_txset_hex_len = 256;
    let oversized_txset = "aa".repeat(129);
    let env = build_tx_sign_req_envelope_with_txset(
        &h.local_keys,
        &h.peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
        &oversized_txset,
    )
    .await;

    let err = h
        .agent
        .process_envelope(env)
        .await
        .expect_err("oversized txset must reject");
    assert!(err.to_string().contains("too large"));
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(
        h.agent
            .db
            .list_pending()
            .await
            .expect("list pending")
            .is_empty()
    );

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn record_auth_event_persists_challenge_and_token_lifecycle() {
    let h = setup_harness("auth_event_lifecycle").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    h.agent
        .record_auth_event(
            escrow_id_hex,
            "challenge_issued",
            Some("nxms-auth"),
            Some("challenge_id=ch_1"),
            None,
        )
        .await
        .expect("challenge issued");
    h.agent
        .record_auth_event(
            escrow_id_hex,
            "challenge_verified",
            Some("nxms-auth"),
            Some("challenge_id=ch_1 actor=buyer"),
            None,
        )
        .await
        .expect("challenge verified");
    h.agent
        .record_auth_event(
            escrow_id_hex,
            "token_issued",
            Some("nxms-auth"),
            Some("jti=jti_1 scope=sign_multisig"),
            Some(AuthEventContext {
                op: Some("sign_multisig".to_string()),
                txset_hash_hex: None,
                proof_arbiter_jti: None,
                proof_arbiter_req_id: None,
                proof_seller_jti: None,
                proof_seller_req_id: None,
            }),
        )
        .await
        .expect("token issued");

    let rows = h.agent.db.list_audit_logs(20).await.expect("list audit");
    let mut kinds = rows
        .iter()
        .map(|r| r.event_kind.clone())
        .collect::<Vec<_>>();
    kinds.sort();
    assert!(kinds.contains(&"challenge_issued".to_string()));
    assert!(kinds.contains(&"challenge_verified".to_string()));
    assert!(kinds.contains(&"token_issued".to_string()));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn record_auth_event_rejects_unknown_kind() {
    let h = setup_harness("auth_event_unknown").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    let err = h
        .agent
        .record_auth_event(
            escrow_id_hex,
            "challenge_used",
            Some("nxms-auth"),
            None,
            None,
        )
        .await
        .expect_err("unknown kind should fail");
    assert!(err.to_string().contains("auth event kind must be one of"));

    let rows = h.agent.db.list_audit_logs(10).await.expect("list audit");
    assert!(rows.is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn record_auth_event_rejects_secret_or_jwt_in_detail() {
    let h = setup_harness("auth_event_detail_secret").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    let err = h
        .agent
        .record_auth_event(
            escrow_id_hex,
            "challenge_issued",
            Some("nxms-auth"),
            Some("Authorization: Bearer eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InNpZ25fbXVsdGlzaWcifQ.c2lnbmF0dXJlX2J5dGVz"),
            None,
        )
        .await
        .expect_err("raw jwt detail must reject");
    assert!(
        err.to_string().contains("detail must not include"),
        "unexpected error: {}",
        err
    );

    let rows = h.agent.db.list_audit_logs(10).await.expect("list audit");
    assert!(rows.is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn record_auth_event_hardening_requires_submit_quorum_context() {
    let mut h = setup_harness("auth_event_submit_require_context").await;
    h.agent.cfg.production_hardening = true;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";

    let err = h
        .agent
        .record_auth_event(
            escrow_id_hex,
            "token_issued",
            Some("nxms-auth"),
            Some("challenge_id=ch_1"),
            Some(AuthEventContext {
                op: Some("submit_multisig".to_string()),
                txset_hash_hex: None,
                proof_arbiter_jti: None,
                proof_arbiter_req_id: None,
                proof_seller_jti: None,
                proof_seller_req_id: None,
            }),
        )
        .await
        .expect_err("missing submit quorum context must reject");
    assert!(
        err.to_string()
            .contains("requires txset_hash_hex and all proof_* fields"),
        "unexpected error: {}",
        err
    );

    let rows = h.agent.db.list_audit_logs(10).await.expect("list audit");
    assert!(rows.is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn sign_multisig_flow_duplicate_req_id_returns_cached_without_second_sign() {
    let mut h = setup_harness("sign_flow_reqid_cache").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "sign-flow-reqid-cache");
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("hash");

    let token_1 = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-sign-1",
    );
    let first = h
        .agent
        .sign_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", Some(&token_1))
        .await
        .expect("first sign should succeed");
    assert_eq!(first.tx_data_hex, "aa11");
    let sign_count_after_first = wallet_call_count(&h.wallet_state, "sign_multisig");
    assert_eq!(sign_count_after_first, 1);

    let token_2 = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-sign-2",
    );
    let second = h
        .agent
        .sign_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", Some(&token_2))
        .await
        .expect("duplicate req_id should return cached response");
    assert_eq!(second.tx_data_hex, first.tx_data_hex);
    assert_eq!(second.tx_hash_list, first.tx_hash_list);
    assert_eq!(wallet_call_count(&h.wallet_state, "sign_multisig"), 1);
    assert!(consumed_jti_exists(&h.db_path, "jti-sign-2"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn submit_multisig_flow_duplicate_req_id_returns_cached_without_second_submit() {
    let mut h = setup_harness("submit_flow_reqid_cache").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "submit-flow-reqid-cache");
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("hash");
    let proof_arbiter_jti = "proof-jti-arbiter";
    let proof_arbiter_req_id =
        sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);
    let proof_seller_jti = "proof-jti-seller";
    let proof_seller_req_id =
        sign_req_id(escrow_id_hex, "sign_multisig", "seller_second", &txset_hash);

    h.agent
        .db
        .record_sign_event(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            &txset_hash,
            proof_arbiter_jti,
            &proof_arbiter_req_id,
        )
        .await
        .expect("seed local arbiter proof");

    let token_1 = build_submit_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-submit-1",
        proof_arbiter_jti,
        &proof_arbiter_req_id,
        proof_seller_jti,
        &proof_seller_req_id,
    );
    let first = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", Some(&token_1))
        .await
        .expect("first submit should succeed");
    assert_eq!(first, vec!["submithash".to_string()]);
    let submit_count_after_first = wallet_call_count(&h.wallet_state, "submit_multisig");
    assert_eq!(submit_count_after_first, 1);

    let token_2 = build_submit_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-submit-2",
        proof_arbiter_jti,
        &proof_arbiter_req_id,
        proof_seller_jti,
        &proof_seller_req_id,
    );
    let second = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", Some(&token_2))
        .await
        .expect("duplicate req_id should return cached submit response");
    assert_eq!(second, first);
    assert_eq!(wallet_call_count(&h.wallet_state, "submit_multisig"), 1);
    assert!(consumed_jti_exists(&h.db_path, "jti-submit-2"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn submit_multisig_flow_rejects_when_arbiter_proof_does_not_match_local_event() {
    let mut h = setup_harness("submit_flow_proof_mismatch").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "submit-flow-proof-mismatch");
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("hash");
    let local_arbiter_jti = "proof-jti-arbiter-local";
    let local_arbiter_req_id =
        sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);
    let seller_jti = "proof-jti-seller";
    let seller_req_id = sign_req_id(escrow_id_hex, "sign_multisig", "seller_second", &txset_hash);
    let submit_req_id = sign_req_id(
        escrow_id_hex,
        "submit_multisig",
        "arbiter_submit",
        &txset_hash,
    );

    h.agent
        .db
        .record_sign_event(
            escrow_id_hex,
            "arbiter",
            "arbiter_first",
            &txset_hash,
            local_arbiter_jti,
            &local_arbiter_req_id,
        )
        .await
        .expect("seed local arbiter proof");

    let token = build_submit_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-submit-proof-mismatch",
        "proof-jti-arbiter-token-mismatch",
        &local_arbiter_req_id,
        seller_jti,
        &seller_req_id,
    );

    let err = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", Some(&token))
        .await
        .expect_err("mismatched arbiter proof should reject submit");
    assert!(
        err.to_string()
            .contains("local arbiter quorum proof mismatch")
    );
    assert_eq!(wallet_call_count(&h.wallet_state, "submit_multisig"), 0);
    assert_eq!(sign_request_status(&h.db_path, &submit_req_id), None);
    assert!(consumed_jti_exists(&h.db_path, "jti-submit-proof-mismatch"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn sign_multisig_flow_rejects_unexpected_recipient_before_wallet_sign() {
    let h = setup_harness("sign_flow_policy_recipient").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    *h.wallet_state
        .describe_address
        .lock()
        .expect("describe address lock") = "attacker_addr".to_string();

    let err = h
        .agent
        .sign_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", None)
        .await
        .expect_err("unexpected recipient must reject sign");
    assert!(err.to_string().contains("not in allowed policy"));
    let calls = wallet_calls(&h.wallet_state);
    assert!(calls.contains(&"describe_transfer".to_string()));
    assert!(!calls.contains(&"sign_multisig".to_string()));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn submit_multisig_flow_rejects_fee_cap_violation_before_wallet_submit() {
    let h = setup_harness("submit_flow_policy_fee").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    *h.wallet_state
        .describe_fee
        .lock()
        .expect("describe_fee lock") = 11;

    let err = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", None)
        .await
        .expect_err("fee violation must reject submit");
    assert!(err.to_string().contains("fee cap violation"));
    let calls = wallet_calls(&h.wallet_state);
    assert!(calls.contains(&"describe_transfer".to_string()));
    assert!(!calls.contains(&"submit_multisig".to_string()));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn submit_multisig_flow_rejects_unlock_time_violation_before_wallet_submit() {
    let h = setup_harness("submit_flow_policy_unlock").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    *h.wallet_state
        .describe_unlock_time
        .lock()
        .expect("describe unlock lock") = 5;

    let err = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", None)
        .await
        .expect_err("unlock_time violation must reject submit");
    assert!(err.to_string().contains("unlock_time policy violation"));
    let calls = wallet_calls(&h.wallet_state);
    assert!(calls.contains(&"describe_transfer".to_string()));
    assert!(!calls.contains(&"submit_multisig".to_string()));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn submit_multisig_flow_rejects_dummy_outputs_violation_before_wallet_submit() {
    let h = setup_harness("submit_flow_policy_dummy").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    *h.wallet_state
        .describe_dummy_outputs
        .lock()
        .expect("describe dummy lock") = 2;

    let err = h
        .agent
        .submit_multisig_flow(escrow_id_hex, EscrowAction::Release, "aa11", None)
        .await
        .expect_err("dummy outputs violation must reject submit");
    assert!(err.to_string().contains("dummy_outputs policy violation"));
    let calls = wallet_calls(&h.wallet_state);
    assert!(calls.contains(&"describe_transfer".to_string()));
    assert!(!calls.contains(&"submit_multisig".to_string()));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_status_gate_blocks_non_pending_without_side_effects() {
    let h = setup_harness("approve_status_gate").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "approved",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, None)
        .await
        .expect_err("status gate must reject non-pending");
    assert!(err.to_string().contains("expected 'pending'"));
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "approved");

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_hash_mismatch_marks_error_and_never_signs() {
    let h = setup_harness("approve_hash_mismatch").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        "55".repeat(32),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, None)
        .await
        .expect_err("hash mismatch must reject");
    assert!(err.to_string().contains("txset hash mismatch"));
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "failed_dead_letter");
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_legacy_sha3_hash_still_allows_flow() {
    let h = setup_harness("approve_legacy_sha3").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        sha3_hex("aa11".as_bytes()),
    )
    .await;

    h.agent
        .approve_pending(id, None)
        .await
        .expect("legacy sha3 compatibility");
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "approved_sent");
    assert!(wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert_eq!(mailbox_pushes(&h.mailbox_state).len(), 1);

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_snapshot_mismatch_marks_error_without_sign_or_send() {
    let h = setup_harness("approve_snapshot_mismatch").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let _snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &"aa".repeat(32),
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, None)
        .await
        .expect_err("snapshot mismatch must reject");
    assert!(err.to_string().contains("pending snapshot mismatch"));
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "failed_dead_letter");
    assert!(wallet_calls(&h.wallet_state).is_empty());
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_policy_mismatch_marks_error_before_sign() {
    let h = setup_harness("approve_policy_mismatch").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    *h.wallet_state
        .describe_address
        .lock()
        .expect("describe address lock") = "attacker_addr".to_string();
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, None)
        .await
        .expect_err("policy mismatch must reject");
    assert!(err.to_string().contains("policy check failed"));
    let calls = wallet_calls(&h.wallet_state);
    assert!(calls.contains(&"describe_transfer".to_string()));
    assert!(!calls.contains(&"sign_multisig".to_string()));
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "failed_dead_letter");
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_token_required_missing_rejects_without_sign() {
    let mut h = setup_harness("approve_token_missing").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "missing");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, None)
        .await
        .expect_err("missing token must reject");
    assert!(err.to_string().contains("action token required"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    let audit = h.agent.db.list_audit_logs(50).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "sign_reject"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_invalid_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_invalid").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "invalid");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .approve_pending(id, Some("invalid.jwt.token"))
        .await
        .expect_err("invalid token must reject");
    assert!(err.to_string().contains("invalid action token"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    let audit = h.agent.db.list_audit_logs(50).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "sign_reject"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_role_round_swap_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_role_round_swap").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "role-round-swap");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-role-round-swap",
    );
    claims.role = "seller".to_string();
    claims.sign_round = "seller_second".to_string();
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("role/round swap token must reject");
    assert!(err.to_string().contains("role mismatch"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_wrong_sandbox_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_wrong_sandbox").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "wrong-sandbox");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-wrong-sandbox",
    );
    claims.sandbox_id = "sbx-other".to_string();
    claims.aud = "sandbox:sbx-other".to_string();
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("wrong sandbox token must reject");
    assert!(err.to_string().contains("invalid action token"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_expired_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_expired").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "expired");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-expired",
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    claims.iat = now.saturating_sub(120);
    claims.nbf = now.saturating_sub(120);
    claims.exp = now.saturating_sub(60);
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("expired token must reject");
    assert!(err.to_string().contains("invalid action token"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_future_iat_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_future_iat").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "future-iat");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-future-iat",
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    claims.iat = now + 30;
    claims.nbf = now;
    claims.exp = now + 90;
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("future iat token must reject");
    assert!(err.to_string().contains("iat is in the future"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_future_nbf_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_future_nbf").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "future-nbf");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-future-nbf",
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    claims.iat = now;
    claims.nbf = now + 60;
    claims.exp = now + 120;
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("future nbf token must reject");
    assert!(err.to_string().contains("invalid action token"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_wrong_wallet_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_wrong_wallet").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "wrong-wallet");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-wrong-wallet",
    );
    claims.wallet_id = "wallet-other".to_string();
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("wrong wallet token must reject");
    assert!(err.to_string().contains("wallet_id mismatch"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_wrong_nettype_token_rejects_without_sign() {
    let mut h = setup_harness("approve_token_wrong_nettype").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "wrong-nettype");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let mut claims = build_sign_action_claims(
        &h.agent,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-wrong-nettype",
    );
    claims.nettype = "mainnet".to_string();
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &fixture.encoding_key,
    )
    .expect("encode");

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("wrong nettype token must reject");
    assert!(err.to_string().contains("nettype mismatch"));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    assert_eq!(get_pending(&h.agent, id).await.status, "pending");

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_consumes_jti_before_wallet_sign() {
    let mut h = setup_harness("approve_consume_order").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "consume-order");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let jti = "jti-order";
    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );
    *h.wallet_state
        .consume_check
        .lock()
        .expect("consume check lock") = Some(ConsumeCheck {
        db_path: h.db_path.clone(),
        jti: jti.to_string(),
    });

    h.agent
        .approve_pending(id, Some(&token))
        .await
        .expect("approve ok");

    let seen = *h
        .wallet_state
        .consumed_seen_on_sign
        .lock()
        .expect("consumed seen lock");
    assert_eq!(seen, Some(true));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn dead_letter_truth_uses_failed_dead_letter_status_and_decision_error_audit() {
    let mut h = setup_harness("dead_letter_truth").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "dead-letter-truth");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    *h.wallet_state
        .describe_address
        .lock()
        .expect("describe_address lock") = "unexpected_addr".to_string();

    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-dead-letter-truth",
    );
    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("policy mismatch must fail");
    assert!(err.to_string().contains("policy check failed"));

    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "failed_dead_letter");
    assert!(
        row.decision_reason
            .as_deref()
            .unwrap_or_default()
            .contains("policy check failed")
    );
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    let audit = h.agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "decision_error"));
    assert!(audit.iter().any(|e| e.decision.as_deref() == Some("dead_letter")));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_start_sign_request_failure_stops_before_consume_and_sign() {
    let mut h = setup_harness("approve_start_req_fail").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "start-req-fail");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let req_id = sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);
    h.agent
        .db
        .start_sign_request(
            &req_id,
            escrow_id_hex,
            "sign_multisig",
            "arbiter_first",
            &txset_hash,
        )
        .await
        .expect("preinsert duplicate req_id");

    let jti = "jti-dup-req";
    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("duplicate req_id must fail");
    assert!(err.to_string().contains("duplicate req_id"));
    assert!(!consumed_jti_exists(&h.db_path, jti));
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_consume_jti_failure_aborts_sign_request() {
    let mut h = setup_harness("approve_consume_fail").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "consume-fail");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let jti = "jti-replay";
    h.agent
        .db
        .consume_action_jti(
            jti,
            escrow_id_hex,
            "sign_multisig",
            "arbiter_first",
            "req-older",
            now_ms() / 1000 + 120,
        )
        .await
        .expect("preconsume jti");

    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );
    let req_id = sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("replayed jti must fail");
    assert!(err.to_string().contains("replayed jti"));
    assert_eq!(sign_request_status(&h.db_path, &req_id), None);
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_wallet_sign_failure_aborts_sign_request() {
    let mut h = setup_harness("approve_wallet_sign_fail").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "wallet-sign-fail");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    *h.wallet_state
        .sign_error_message
        .lock()
        .expect("sign error lock") = Some("forced sign failure".to_string());

    let jti = "jti-sign-fail";
    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );
    let req_id = sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);

    let err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("sign failure should bubble");
    assert!(err.to_string().contains("forced sign failure"));
    assert!(wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    assert_eq!(sign_request_status(&h.db_path, &req_id), None);
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_happy_path_has_expected_side_effects() {
    let mut h = setup_harness("approve_happy_path").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "happy");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let jti = "jti-happy";
    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );
    let req_id = sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);

    h.agent
        .approve_pending(id, Some(&token))
        .await
        .expect("approve happy path");

    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "approved_sent");

    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    let body = decode_push_body(&pushes[0], &h.local_keys, &h.peer_keys);
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    assert_eq!(resp.signed_tx_data_hex.as_deref(), Some("aa11"));

    assert_eq!(
        sign_request_status(&h.db_path, &req_id).as_deref(),
        Some("completed")
    );
    let has_sign_event = h
        .agent
        .db
        .has_sign_event(escrow_id_hex, "arbiter", "arbiter_first", &txset_hash)
        .await
        .expect("has sign event");
    assert!(has_sign_event);

    let audit = h.agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "decision_approved"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn signer_delivers_approved_response_to_real_mailbox_app() {
    let (mailbox_url, mailbox_db_path) = spawn_real_mailbox_server("signer_boundary").await;
    let wallet_state = Arc::new(WalletMockState::default());
    let wallet_url = spawn_server(
        Router::new()
            .route("/json_rpc", post(wallet_rpc_handler))
            .with_state(wallet_state.clone()),
    )
    .await;

    let local_keys = Keys::generate().expect("local keys");
    let peer_keys = Keys::generate().expect("peer keys");
    let signer_db_path = unique_db_path("signer_real_mailbox");
    let mut agent = make_agent(
        mailbox_url.clone(),
        wallet_url,
        signer_db_path.clone(),
        clone_keys(&local_keys),
        clone_keys(&peer_keys),
    )
    .await;
    let fixture = install_action_token_verifier(&mut agent, true, "real-mailbox-boundary");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let token = build_sign_action_token(
        &agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-real-mailbox-boundary",
    );
    agent
        .approve_pending(id, Some(&token))
        .await
        .expect("approve through real mailbox");

    let mailbox_client = MailboxClient::builder(&mailbox_url)
        .expect("mailbox builder")
        .pull_token("peer1-pull-token-123456")
        .ack_token("peer1-ack-token-123456")
        .admin_token("admin-token-123456")
        .build()
        .expect("mailbox client");

    let pulled = mailbox_client
        .pull("peer1", Some(1), Some(0))
        .await
        .expect("pull real mailbox response");
    assert_eq!(pulled.messages.len(), 1);
    let body = decode_push_body(&serde_json::json!({"envelope": pulled.messages[0].envelope}), &local_keys, &peer_keys);
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    assert_eq!(resp.signed_tx_data_hex.as_deref(), Some("aa11"));

    mailbox_client
        .ack(&pulled.messages[0].receipt)
        .await
        .expect("ack real mailbox response");
    let stats = mailbox_client.admin_stats().await.expect("admin stats");
    assert_eq!(stats.total_rows, 0);

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&signer_db_path);
    remove_file_quiet(&mailbox_db_path);
}

#[tokio::test]
async fn transport_mailbox_signer_smoke_flow_uses_real_mailbox_app() {
    let (mailbox_url, mailbox_db_path) = spawn_real_mailbox_server("transport_signer_smoke").await;
    let wallet_state = Arc::new(WalletMockState::default());
    let wallet_url = spawn_server(
        Router::new()
            .route("/json_rpc", post(wallet_rpc_handler))
            .with_state(wallet_state.clone()),
    )
    .await;

    let local_keys = Keys::generate().expect("local keys");
    let peer_keys = Keys::generate().expect("peer keys");
    let signer_db_path = unique_db_path("transport_signer_smoke");
    let mut agent = make_agent(
        mailbox_url.clone(),
        wallet_url,
        signer_db_path.clone(),
        clone_keys(&local_keys),
        clone_keys(&peer_keys),
    )
    .await;
    let fixture = install_action_token_verifier(&mut agent, true, "transport-signer-smoke");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");

    let ingress_client = MailboxClient::builder(&mailbox_url)
        .expect("ingress builder")
        .push_token("push-token-123456")
        .build()
        .expect("ingress client");
    let req_env = build_tx_sign_req_envelope(
        &local_keys,
        &peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;
    ingress_client
        .push(&req_env, Some(60))
        .await
        .expect("push inbound envelope");

    let pulled = agent.mailbox_pull_with_retry().await.expect("signer pull");
    assert_eq!(pulled.messages.len(), 1);
    let receipt = pulled.messages[0].receipt.clone();
    agent
        .process_envelope(pulled.messages[0].envelope.clone())
        .await
        .expect("process inbound envelope");
    agent
        .mailbox_ack_with_retry(&receipt)
        .await
        .expect("ack inbound receipt");

    let pending = agent.db.list_pending().await.expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, "pending");

    let token = build_sign_action_token(
        &agent,
        &fixture,
        escrow_id_hex,
        &pending[0].txset_hash_hex,
        &snapshot_hash_for_token,
        "jti-transport-signer-smoke",
    );
    agent
        .approve_pending(pending[0].id, Some(&token))
        .await
        .expect("approve pending");

    let peer_client = MailboxClient::builder(&mailbox_url)
        .expect("peer builder")
        .pull_token("peer1-pull-token-123456")
        .ack_token("peer1-ack-token-123456")
        .admin_token("admin-token-123456")
        .build()
        .expect("peer client");
    let peer_pulled = peer_client
        .pull("peer1", Some(1), Some(0))
        .await
        .expect("pull outbound envelope");
    assert_eq!(peer_pulled.messages.len(), 1);
    let body = decode_push_body(
        &serde_json::json!({"envelope": peer_pulled.messages[0].envelope}),
        &local_keys,
        &peer_keys,
    );
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    assert_eq!(resp.signed_tx_data_hex.as_deref(), Some("aa11"));

    peer_client
        .ack(&peer_pulled.messages[0].receipt)
        .await
        .expect("ack outbound receipt");
    let stats = peer_client.admin_stats().await.expect("admin stats");
    assert_eq!(stats.total_rows, 0);

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&signer_db_path);
    remove_file_quiet(&mailbox_db_path);
}

#[tokio::test]
async fn transport_sign_submit_smoke_flow_uses_real_mailbox_app() {
    let (mailbox_url, mailbox_db_path) =
        spawn_real_mailbox_server("transport_sign_submit_smoke").await;
    let wallet_state = Arc::new(WalletMockState::default());
    let wallet_url = spawn_server(
        Router::new()
            .route("/json_rpc", post(wallet_rpc_handler))
            .with_state(wallet_state.clone()),
    )
    .await;

    let local_keys = Keys::generate().expect("local keys");
    let peer_keys = Keys::generate().expect("peer keys");
    let signer_db_path = unique_db_path("transport_sign_submit_smoke");
    let mut agent = make_agent(
        mailbox_url.clone(),
        wallet_url,
        signer_db_path.clone(),
        clone_keys(&local_keys),
        clone_keys(&peer_keys),
    )
    .await;
    let fixture = install_action_token_verifier(&mut agent, true, "transport-sign-submit-smoke");

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");

    let ingress_client = MailboxClient::builder(&mailbox_url)
        .expect("ingress builder")
        .push_token("push-token-123456")
        .build()
        .expect("ingress client");
    let req_env = build_tx_sign_req_envelope(
        &local_keys,
        &peer_keys,
        escrow_id_hex,
        &snapshot_hash,
        1,
    )
    .await;
    ingress_client
        .push(&req_env, Some(60))
        .await
        .expect("push inbound envelope");

    let pulled = agent.mailbox_pull_with_retry().await.expect("signer pull");
    assert_eq!(pulled.messages.len(), 1);
    let receipt = pulled.messages[0].receipt.clone();
    agent
        .process_envelope(pulled.messages[0].envelope.clone())
        .await
        .expect("process inbound envelope");
    agent
        .mailbox_ack_with_retry(&receipt)
        .await
        .expect("ack inbound receipt");

    let pending = agent.db.list_pending().await.expect("list pending");
    assert_eq!(pending.len(), 1);
    let txset_hash = pending[0].txset_hash_hex.clone();
    let sign_jti = "jti-transport-sign-submit-smoke";
    let sign_token = build_sign_action_token(
        &agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        sign_jti,
    );
    agent
        .approve_pending(pending[0].id, Some(&sign_token))
        .await
        .expect("approve pending");

    let peer_client = MailboxClient::builder(&mailbox_url)
        .expect("peer builder")
        .pull_token("peer1-pull-token-123456")
        .ack_token("peer1-ack-token-123456")
        .admin_token("admin-token-123456")
        .build()
        .expect("peer client");
    let peer_pulled = peer_client
        .pull("peer1", Some(1), Some(0))
        .await
        .expect("pull outbound envelope");
    assert_eq!(peer_pulled.messages.len(), 1);
    let body = decode_push_body(
        &serde_json::json!({"envelope": peer_pulled.messages[0].envelope}),
        &local_keys,
        &peer_keys,
    );
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    let signed_tx_data_hex = resp
        .signed_tx_data_hex
        .clone()
        .expect("signed tx data");
    peer_client
        .ack(&peer_pulled.messages[0].receipt)
        .await
        .expect("ack outbound receipt");

    let proof_arbiter_req_id =
        sign_req_id(escrow_id_hex, "sign_multisig", "arbiter_first", &txset_hash);
    let proof_seller_jti = "seller-proof-jti-transport-sign-submit";
    let proof_seller_req_id =
        sign_req_id(escrow_id_hex, "sign_multisig", "seller_second", &txset_hash);
    let submit_token = build_submit_action_token(
        &agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-submit-transport-sign-submit",
        sign_jti,
        &proof_arbiter_req_id,
        proof_seller_jti,
        &proof_seller_req_id,
    );
    let submitted = agent
        .submit_multisig_flow(
            escrow_id_hex,
            EscrowAction::Release,
            &signed_tx_data_hex,
            Some(&submit_token),
        )
        .await
        .expect("submit multisig");
    assert_eq!(submitted, vec!["submithash".to_string()]);
    assert!(wallet_calls(&wallet_state).contains(&"submit_multisig".to_string()));

    let audit = agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "submit_success"));

    let stats = peer_client.admin_stats().await.expect("admin stats");
    assert_eq!(stats.total_rows, 0);

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&signer_db_path);
    remove_file_quiet(&mailbox_db_path);
}

#[tokio::test]
async fn approve_pending_retry_from_approved_sending_resends_without_resign() {
    let mut h = setup_harness("approve_retry_approved_sending").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "retry-approved-sending");
    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = true;

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let jti = "jti-retry-approved-sending";
    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        jti,
    );

    let first_err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("first send should fail while mailbox push is forced down");
    assert!(first_err.to_string().contains("mailbox http"));
    let row_after_fail = get_pending(&h.agent, id).await;
    assert_eq!(row_after_fail.status, "approved_sending");
    assert!(row_after_fail.decision_reason.is_some());
    let staged: Value = serde_json::from_str(
        row_after_fail
            .decision_reason
            .as_deref()
            .expect("approved_sending has staged json"),
    )
    .expect("approved staged json");
    let staged_out_seq = staged
        .get("out_seq")
        .and_then(Value::as_u64)
        .expect("approved staged out_seq");
    assert!(wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));

    clear_wallet_calls(&h.wallet_state);
    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = false;
    h.agent
        .approve_pending(id, None)
        .await
        .expect("retry from approved_sending should resend and finalize");

    let row_final = get_pending(&h.agent, id).await;
    assert_eq!(row_final.status, "approved_sent");
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    assert_eq!(push_envelope_seq(&pushes[0]), staged_out_seq);
    let body = decode_push_body(&pushes[0], &h.local_keys, &h.peer_keys);
    let EscrowBody::TxSignResp(resp) = body else {
        panic!("expected TxSignResp body");
    };
    assert!(resp.approved);
    assert_eq!(resp.signed_tx_data_hex.as_deref(), Some("aa11"));

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn approve_pending_retry_from_approved_sending_recovers_after_restart() {
    let mut h = setup_harness("approve_retry_restart").await;
    let fixture = install_action_token_verifier(&mut h.agent, true, "retry-approved-restart");
    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = true;

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot).expect("policy hash");
    let txset_hash = txset_sha256_hex("aa11").expect("txset hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_hash.clone(),
    )
    .await;

    let token = build_sign_action_token(
        &h.agent,
        &fixture,
        escrow_id_hex,
        &txset_hash,
        &snapshot_hash_for_token,
        "jti-retry-approved-restart",
    );
    let first_err = h
        .agent
        .approve_pending(id, Some(&token))
        .await
        .expect_err("first send should fail while mailbox push is forced down");
    assert!(first_err.to_string().contains("mailbox http"));
    let row_after_fail = get_pending(&h.agent, id).await;
    assert_eq!(row_after_fail.status, "approved_sending");
    let staged: Value = serde_json::from_str(
        row_after_fail
            .decision_reason
            .as_deref()
            .expect("approved_sending has staged json"),
    )
    .expect("approved staged json");
    let staged_out_seq = staged
        .get("out_seq")
        .and_then(Value::as_u64)
        .expect("approved staged out_seq");
    assert_eq!(wallet_call_count(&h.wallet_state, "sign_multisig"), 1);

    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = false;
    let restarted_agent = make_agent(
        h.mailbox_url.clone(),
        h.wallet_url.clone(),
        h.db_path.clone(),
        clone_keys(&h.local_keys),
        clone_keys(&h.peer_keys),
    )
    .await;
    clear_wallet_calls(&h.wallet_state);
    restarted_agent
        .approve_pending(id, None)
        .await
        .expect("retry after restart should resend and finalize");

    let row_final = restarted_agent
        .db
        .get_pending(id)
        .await
        .expect("get pending")
        .expect("pending exists");
    assert_eq!(row_final.status, "approved_sent");
    assert!(!wallet_calls(&h.wallet_state).contains(&"sign_multisig".to_string()));
    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    assert_eq!(push_envelope_seq(&pushes[0]), staged_out_seq);

    remove_file_quiet(&fixture.key_path);
    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn reject_pending_status_gate_blocks_non_pending_without_side_effects() {
    let h = setup_harness("reject_status_gate").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "approved",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .reject_pending(id, "manual reject")
        .await
        .expect_err("reject status gate should fail");
    assert!(
        err.to_string()
            .contains("expected 'pending' or 'rejected_sending'")
    );
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());
    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "approved");

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn reject_pending_happy_path_sends_error_and_marks_rejected() {
    let h = setup_harness("reject_happy").await;
    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    h.agent
        .reject_pending(id, "manual reject")
        .await
        .expect("reject ok");

    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "rejected");

    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    let body = decode_push_body(&pushes[0], &h.local_keys, &h.peer_keys);
    let EscrowBody::Err(err) = body else {
        panic!("expected error body");
    };
    assert_eq!(err.code, "tx_sign_rejected");
    assert_eq!(err.reason, "manual reject");

    let audit = h.agent.db.list_audit_logs(200).await.expect("audit list");
    assert!(audit.iter().any(|e| e.event_kind == "decision_rejected"));

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn reject_pending_send_failure_keeps_status_rejected_sending() {
    let h = setup_harness("reject_send_fail").await;
    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = true;

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let err = h
        .agent
        .reject_pending(id, "manual reject")
        .await
        .expect_err("send failure should bubble");
    assert!(err.to_string().contains("mailbox http"));

    let row = get_pending(&h.agent, id).await;
    assert_eq!(row.status, "rejected_sending");
    assert!(row.decision_reason.is_some());
    assert!(mailbox_pushes(&h.mailbox_state).is_empty());

    remove_file_quiet(&h.db_path);
}

#[tokio::test]
async fn reject_pending_retry_from_rejected_sending_resends_with_staged_seq() {
    let h = setup_harness("reject_retry_rejected_sending").await;
    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = true;

    let escrow_id_hex = "00112233445566778899aabbccddeeff";
    let snapshot = seed_active_snapshot(&h.agent.db, escrow_id_hex).await;
    let snapshot_hash = canonical_hash_hex(&snapshot).expect("snapshot hash");
    let id = enqueue_pending(
        &h.agent,
        escrow_id_hex,
        1,
        "pending",
        &snapshot_hash,
        txset_sha256_hex("aa11").expect("txset hash"),
    )
    .await;

    let first_err = h
        .agent
        .reject_pending(id, "manual reject")
        .await
        .expect_err("first send should fail while mailbox push is forced down");
    assert!(first_err.to_string().contains("mailbox http"));
    let row_after_fail = get_pending(&h.agent, id).await;
    assert_eq!(row_after_fail.status, "rejected_sending");
    let staged: Value = serde_json::from_str(
        row_after_fail
            .decision_reason
            .as_deref()
            .expect("rejected_sending has staged json"),
    )
    .expect("rejected staged json");
    let staged_out_seq = staged
        .get("out_seq")
        .and_then(Value::as_u64)
        .expect("rejected staged out_seq");

    *h.mailbox_state.fail_push.lock().expect("fail_push lock") = false;
    h.agent
        .reject_pending(id, "different reason ignored on retry")
        .await
        .expect("retry from rejected_sending should resend and finalize");

    let row_final = get_pending(&h.agent, id).await;
    assert_eq!(row_final.status, "rejected");
    assert_eq!(row_final.decision_reason.as_deref(), Some("manual reject"));

    let pushes = mailbox_pushes(&h.mailbox_state);
    assert_eq!(pushes.len(), 1);
    assert_eq!(push_envelope_seq(&pushes[0]), staged_out_seq);
    let body = decode_push_body(&pushes[0], &h.local_keys, &h.peer_keys);
    let EscrowBody::Err(err) = body else {
        panic!("expected error body");
    };
    assert_eq!(err.code, "tx_sign_rejected");
    assert_eq!(err.reason, "manual reject");

    remove_file_quiet(&h.db_path);
}
