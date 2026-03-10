#![cfg(feature = "crypto")]

use nxms_transport::crypto::{Keys, SealedPacket, decrypt, encrypt, suite_kem_id, suite_sig_id};
use nxms_transport::wire::{
    ESCROW_APP_PROTO_V1, MsgType, NXMS_PROTO_V1, NxmsEnvelope, NxmsPayload, msg_type_key,
};

#[test]
fn crypto_roundtrip_encrypt_decrypt() {
    let sender = Keys::generate().expect("sender keys");
    let recipient = Keys::generate().expect("recipient keys");

    let sender_sig_sk = sender.sig_sk_zeroizing().expect("sender sig sk");
    let sender_sig_pk = sender.sig_pk().expect("sender sig pk");
    let recipient_kem_pk = recipient.kem_pk().expect("recipient kem pk");
    let recipient_kem_sk = recipient.kem_sk_zeroizing().expect("recipient kem sk");

    let escrow_id = [7u8; 16];
    let escrow_id_hex = hex::encode(escrow_id);
    let seq: u64 = 1;

    let msg_type = MsgType::PrepareInfo;
    let payload = NxmsPayload {
        app_proto: ESCROW_APP_PROTO_V1.to_string(),
        msg_type: msg_type.clone(),
        escrow_id_hex: escrow_id_hex.clone(),
        from: "alice".to_string(),
        to: "bob".to_string(),
        seq,
        data: "hello".to_string(),
    };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let sealed = encrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &recipient_kem_pk,
        sender_sig_sk.as_slice(),
        &plaintext,
    )
    .expect("encrypt");

    let env = NxmsEnvelope {
        proto: NXMS_PROTO_V1.to_string(),
        kem_id: suite_kem_id().to_string(),
        sig_id: suite_sig_id().to_string(),
        msg_type: msg_type.clone(),
        escrow_id_hex: escrow_id_hex.clone(),
        from: "alice".to_string(),
        to: "bob".to_string(),
        seq,
        kem_ct_b64: sealed.kem_ct_b64.clone(),
        nonce_b64: sealed.nonce_b64.clone(),
        ciphertext_b64: sealed.ciphertext_b64.clone(),
        tag_b64: sealed.tag_b64.clone(),
        sig_b64: sealed.sig_b64.clone(),
    };

    let sealed2 = SealedPacket {
        kem_ct_b64: env.kem_ct_b64,
        nonce_b64: env.nonce_b64,
        ciphertext_b64: env.ciphertext_b64,
        tag_b64: env.tag_b64,
        sig_b64: env.sig_b64,
    };

    let out = decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &sealed2,
        recipient_kem_sk.as_slice(),
        &sender_sig_pk,
    )
    .expect("decrypt");
    let payload2: NxmsPayload = serde_json::from_slice(&out).expect("payload2 json");

    assert_eq!(payload2.data, "hello");
    assert_eq!(payload2.seq, seq);
    assert_eq!(payload2.escrow_id_hex, escrow_id_hex);
    assert_eq!(payload2.from, "alice");
    assert_eq!(payload2.to, "bob");
}
