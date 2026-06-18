use nxms_meta::Node;

#[tokio::test]
async fn secure_ping_pong() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let node_a = Node::generate("127.0.0.1:0").expect("Node A keygen");
    let node_b = Node::generate("127.0.0.1:0").expect("Node B keygen");

    // Use OS-assigned ports for Node B listener, Node A connects to Node B
    let listener = nxms_transport::p2p::listen("127.0.0.1:0").await.expect("listener");
    let b_addr = listener.local_addr().unwrap();
    let b_port = b_addr.port();

    // Re-create node_b with the actual port
    let node_b = Node {
        keys: node_b.keys.clone(),
        listen_addr: format!("127.0.0.1:{b_port}"),
    };

    let node_a = Node {
        keys: node_a.keys.clone(),
        listen_addr: format!("127.0.0.1:{}", 0),
    };

    // Use the listener we created instead of creating a new one inside run_ping_pong
    let a_kem_pk = node_a.kem_pk().unwrap();
    let a_sig_pk = node_a.sig_pk().unwrap();
    let b_kem_pk = node_b.kem_pk().unwrap();
    let b_sig_pk = node_b.sig_pk().unwrap();

    let mut chan_a = node_a.dial_secure(&node_b.listen_addr, b_kem_pk.clone(), b_sig_pk.clone()).await.expect("dial");
    let mut chan_b = node_b.accept_secure(&listener, a_kem_pk, a_sig_pk).await.expect("accept");

    let nonce = "42";
    let ping = serde_json::json!({"msg":"PING","nonce":nonce});
    let ping_bytes = serde_json::to_vec(&ping).unwrap();

    tracing::info!("[Node A] sending encrypted PING");
    chan_a.send("PING", &ping_bytes).await.expect("send PING");

    tracing::info!("[Node B] waiting for message");
    let recv_bytes = chan_b.recv("PING").await.expect("recv PING");
    let recv_ping: serde_json::Value = serde_json::from_slice(&recv_bytes).unwrap();

    assert_eq!(recv_ping["msg"], "PING");
    tracing::info!("[Node B] decrypted PING, Falcon signature valid");

    let pong = serde_json::json!({"msg":"PONG","from":"B","reply_to":nonce});
    let pong_bytes = serde_json::to_vec(&pong).unwrap();

    tracing::info!("[Node B] sending encrypted PONG");
    chan_b.send("PONG", &pong_bytes).await.expect("send PONG");

    let pong_recv = chan_a.recv("PONG").await.expect("recv PONG");
    let pong_data: serde_json::Value = serde_json::from_slice(&pong_recv).unwrap();

    assert_eq!(pong_data["msg"], "PONG");
    tracing::info!("[Node A] decrypted PONG, Falcon signature valid");
    tracing::info!("[Orchestrator] Test Secure Ping: PASSED");
}

#[tokio::test]
async fn secure_ping_rejects_tampered_signature() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let node_a = Node::generate("127.0.0.1:8002").expect("Node A keygen");
    let node_b = Node::generate("127.0.0.1:8001").expect("Node B keygen");

    // Use wrong keys — Node B uses its own public key as "sender's" key,
    // so decryption+verification should fail because the signature
    // was created by Node A's key but verified against Node B's key.
    let result = run_ping_pong_corrupted(&node_a, &node_b).await;

    assert!(
        result.is_err(),
        "Red Team: tampered connection MUST be rejected (Zero Trust)"
    );
    tracing::info!(
        "[Red Team] Pakiet ze zlym kluczem odrzucony: {}",
        result.unwrap_err()
    );
}

/// Like run_ping_pong but Node B uses its own public keys instead of Node A's
/// when verifying. This simulates a MITM or misconfigured peer.
async fn run_ping_pong_corrupted(
    node_a: &Node,
    node_b: &Node,
) -> anyhow::Result<()> {
    use nxms_transport::p2p::{SecureChannel, listen};

    let listener = listen(&node_b.listen_addr).await?;

    // Correct keys for encryption
    let b_kem_pk = node_b.kem_pk()?;
    let b_sig_pk = node_b.sig_pk()?;

    // Node A dials with correct B keys
    let mut chan_a = SecureChannel::new(
        nxms_transport::p2p::dial(&node_b.listen_addr).await?,
        node_a.keys.clone(),
        b_kem_pk,
        b_sig_pk,
    );

    // Node B accepts but uses ITS OWN public key to verify (WRONG!)
    let (stream, _addr) = listener.accept().await?;
    let mut chan_b = SecureChannel::new(
        stream,
        node_b.keys.clone(),
        node_b.kem_pk()?,
        node_b.sig_pk()?,
    ); // ← uses B's pubkeys instead of A's

    let ping = serde_json::json!({"msg":"PING","nonce":"42"});
    let ping_bytes = serde_json::to_vec(&ping)?;

    chan_a.send("PING", &ping_bytes).await?;

    // This should FAIL because Node B tries to verify Node A's signature
    // with Node B's public key
    chan_b.recv("PING").await.map(|_| ())
}
