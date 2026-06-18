use anyhow::Result;
use nxms_transport::crypto::Keys;
use nxms_transport::p2p::listen;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const USAGE: &str = r#"
nexum-node — NXMS mesh node

USAGE:
  nexum-node run
  nexum-node gen-identity --id <ID> --out-dir <DIR>
  nexum-node ping --peer <ID> --vault <DIR> --peers <JSON>

ENV:
  NODE_ID       node identifier (default: node-01)
  LISTEN_HOST   bind address (default: 0.0.0.0)
  LISTEN_PORT   bind port (default: 9000)
  VAULT_DIR     key storage directory (default: /data/vault)
  PEERS_JSON    path to peers.json (default: peers.json)
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerInfo {
    id: String,
    addr: String,
    kem_pk_b64: String,
    sig_pk_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeersConfig {
    nodes: Vec<PeerInfo>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 && args[1] == "gen-identity" {
        let mut id = String::new();
        let mut out_dir = String::new();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--id" => { i += 1; id = args.get(i).cloned().unwrap_or_default(); }
                "--out-dir" => { i += 1; out_dir = args.get(i).cloned().unwrap_or_default(); }
                _ => {}
            }
            i += 1;
        }
        if id.is_empty() || out_dir.is_empty() {
            eprintln!("Usage: nexum-node gen-identity --id <ID> --out-dir <DIR>");
            std::process::exit(1);
        }
        return gen_identity(&id, &out_dir);
    }

    if args.len() >= 2 && args[1] == "ping" {
        let mut peer = String::new();
        let mut vault = String::new();
        let mut peers_path = String::new();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--peer" => { i += 1; peer = args.get(i).cloned().unwrap_or_default(); }
                "--vault" => { i += 1; vault = args.get(i).cloned().unwrap_or_default(); }
                "--peers" => { i += 1; peers_path = args.get(i).cloned().unwrap_or_default(); }
                _ => {}
            }
            i += 1;
        }
        if peer.is_empty() || vault.is_empty() || peers_path.is_empty() {
            eprintln!("Usage: nexum-node ping --peer <ID> --vault <DIR> --peers <JSON>");
            std::process::exit(1);
        }
        return cmd_ping(&peer, &vault, &peers_path).await;
    }

    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    run_node().await
}

fn gen_identity(id: &str, out_dir: &str) -> Result<()> {
    let keys = Keys::generate()?;
    std::fs::create_dir_all(out_dir)?;

    let key_path = format!("{out_dir}/keys.json");
    std::fs::write(&key_path, serde_json::to_string_pretty(&keys)?)?;

    let identity = serde_json::json!({
        "id": id,
        "kem_pk_b64": keys.kem_pk_b64,
        "sig_pk_b64": keys.sig_pk_b64,
    });
    let identity_path = format!("{out_dir}/identity.json");
    std::fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;

    println!("OK {id} → {out_dir}");
    Ok(())
}

async fn cmd_ping(peer_id: &str, vault_dir: &str, peers_path: &str) -> Result<()> {
    let keys = load_or_generate_keys(vault_dir, "cli")?;
    let peers = load_peers(peers_path)?;

    let target = peers
        .nodes
        .iter()
        .find(|p| p.id == peer_id)
        .ok_or_else(|| anyhow::anyhow!("Peer '{peer_id}' not found in peers.json"))?;

    let kem_pk = base64_decode(&target.kem_pk_b64)?;
    let sig_pk = base64_decode(&target.sig_pk_b64)?;

    let mut stream = tokio::net::TcpStream::connect(&target.addr).await?;

    let ping = serde_json::json!({"msg": "PING", "from": "cli", "nonce": "1"});
    let ping_bytes = serde_json::to_vec(&ping)?;

    let sig_sk = keys.sig_sk_zeroizing()?;
    let sealed = nxms_transport::crypto::encrypt(
        "local", "peer", "PING", &[0u8; 16], 1,
        &kem_pk, sig_sk.as_slice(), &ping_bytes,
    )?;

    let wire = serde_json::to_vec(&sealed)?;
    nxms_transport::tor_net::write_frame(&mut stream, &wire).await?;

    let pong_wire = nxms_transport::tor_net::read_frame_default(&mut stream).await?;
    let pong_sealed: nxms_transport::crypto::SealedPacket = serde_json::from_slice(&pong_wire)?;

    let kem_sk = keys.kem_sk_zeroizing()?;
    let pong_data = nxms_transport::crypto::decrypt(
        "local", "peer", "PONG", &[0u8; 16], 1,
        &pong_sealed, kem_sk.as_slice(), &sig_pk,
    )?;

    let pong: serde_json::Value = serde_json::from_slice(&pong_data)?;
    println!("PONG from {}: {}", peer_id, pong);
    Ok(())
}

async fn run_node() -> Result<()> {
    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "node-01".into());
    let listen_host = std::env::var("LISTEN_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let listen_port: u16 = std::env::var("LISTEN_PORT")
        .unwrap_or_else(|_| "9000".into())
        .parse()
        .expect("LISTEN_PORT must be a u16");
    let peers_json = std::env::var("PEERS_JSON").unwrap_or_else(|_| "peers.json".into());
    let vault_dir = std::env::var("VAULT_DIR").unwrap_or_else(|_| "/data/vault".into());

    let listen_addr = format!("{listen_host}:{listen_port}");

    // Load or generate identity
    let keys = load_or_generate_keys(&vault_dir, &node_id)?;
    let peers = load_peers(&peers_json)?;

    tracing::info!(%node_id, %listen_addr, "Node starting");

    // Pre-decode all peer public keys
    let peer_pubkeys: Vec<(String, Vec<u8>, Vec<u8>)> = peers
        .nodes
        .iter()
        .filter(|p| p.id != node_id)
        .map(|p| {
            let kem = base64_decode(&p.kem_pk_b64).expect("Invalid kem_pk_b64");
            let sig = base64_decode(&p.sig_pk_b64).expect("Invalid sig_pk_b64");
            (p.id.clone(), kem, sig)
        })
        .collect();

    let listener = listen(&listen_addr).await?;
    tracing::info!(%node_id, "Listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tracing::info!(%node_id, %peer_addr, "Connection accepted");

        let keys = keys.clone();
        let peer_pubkeys = peer_pubkeys.clone();
        let node_id = node_id.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, keys, peer_pubkeys, &node_id, peer_addr).await {
                tracing::error!(%node_id, %peer_addr, error=%e, "Connection handler failed");
            }
        });
    }
}

fn load_or_generate_keys(vault_dir: &str, node_id: &str) -> Result<Keys> {
    let key_path = format!("{vault_dir}/keys.json");

    if let Ok(data) = std::fs::read_to_string(&key_path) {
        let keys: Keys = serde_json::from_str(&data)?;
        tracing::info!(%node_id, "Loaded existing identity");
        return Ok(keys);
    }

    let keys = Keys::generate()?;
    std::fs::create_dir_all(vault_dir)?;
    std::fs::write(&key_path, serde_json::to_string_pretty(&keys)?)?;

    let info = serde_json::json!({
        "id": node_id,
        "kem_pk_b64": keys.kem_pk_b64,
        "sig_pk_b64": keys.sig_pk_b64,
    });
    std::fs::write(
        format!("{vault_dir}/identity.json"),
        serde_json::to_string_pretty(&info)?,
    )?;

    tracing::info!(%node_id, "Generated new identity");
    Ok(keys)
}

fn load_peers(path: &str) -> Result<PeersConfig> {
    let data = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    keys: Keys,
    peer_pubkeys: Vec<(String, Vec<u8>, Vec<u8>)>,
    node_id: &str,
    peer_addr: SocketAddr,
) -> Result<()> {
    let wire = nxms_transport::tor_net::read_frame_default(&mut stream).await?;

    let sealed: nxms_transport::crypto::SealedPacket = serde_json::from_slice(&wire)?;

    let kem_sk = keys.kem_sk_zeroizing()?;
    let mut plaintext: Option<Vec<u8>> = None;
    let mut peer_id = "unknown".to_string();
    let mut peer_kem_pk = Vec::new();

    for (id, kem, sig) in &peer_pubkeys {
        let result = nxms_transport::crypto::decrypt(
            "local",
            "peer",
            "PING",
            &[0u8; 16],
            1,
            &sealed,
            kem_sk.as_slice(),
            sig,
        );
        if let Ok(data) = result {
            plaintext = Some(data);
            peer_id = id.clone();
            peer_kem_pk = kem.clone();
            break;
        }
    }

    let data = plaintext.ok_or_else(|| anyhow::anyhow!("Could not identify peer or decrypt message"))?;
    let ping: serde_json::Value = serde_json::from_slice(&data)?;

    tracing::info!(%node_id, %peer_id, %peer_addr, ping=%ping["msg"].as_str().unwrap_or("?"), "Received PING");

    let pong = serde_json::json!({"msg": "PONG", "from": node_id, "reply_to": ping["msg"]});
    let pong_bytes = serde_json::to_vec(&pong)?;

    let sig_sk = keys.sig_sk_zeroizing()?;
    let sealed_pong = nxms_transport::crypto::encrypt(
        "local",
        "peer",
        "PONG",
        &[0u8; 16],
        1,
        &peer_kem_pk,
        sig_sk.as_slice(),
        &pong_bytes,
    )?;

    let wire_pong = serde_json::to_vec(&sealed_pong)?;
    nxms_transport::tor_net::write_frame(&mut stream, &wire_pong).await?;

    tracing::info!(%node_id, %peer_id, "Sent PONG");
    Ok(())
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}
