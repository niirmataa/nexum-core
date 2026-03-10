#![cfg(feature = "crypto")]

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nxms_transport::crypto::{Keys, SealedPacket, decrypt, encrypt};
use nxms_transport::wire::{MsgType, msg_type_key};

fn setup_packet() -> (Vec<u8>, Vec<u8>, [u8; 16], u64, SealedPacket, MsgType) {
    let sender = Keys::generate().expect("sender keys");
    let recipient = Keys::generate().expect("recipient keys");

    let sender_sig_sk = sender.sig_sk_zeroizing().expect("sender sig sk");
    let sender_sig_pk = sender.sig_pk().expect("sender sig pk");
    let recipient_kem_pk = recipient.kem_pk().expect("recipient kem pk");
    let recipient_kem_sk = recipient.kem_sk_zeroizing().expect("recipient kem sk");

    let escrow_id = [9u8; 16];
    let seq: u64 = 11;
    let msg_type = MsgType::TxSignReq;
    let plaintext = br#"{"kind":"tx_sign_req","data":"abcd"}"#.to_vec();

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

    (
        recipient_kem_sk.as_slice().to_vec(),
        sender_sig_pk,
        escrow_id,
        seq,
        sealed,
        msg_type,
    )
}

#[test]
fn decrypt_rejects_tampered_tag() {
    let (recipient_kem_sk, sender_sig_pk, escrow_id, seq, mut sealed, msg_type) = setup_packet();
    let mut tag = B64.decode(sealed.tag_b64.as_bytes()).expect("decode tag");
    tag[0] ^= 0x01;
    sealed.tag_b64 = B64.encode(tag);

    let err = decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &sealed,
        &recipient_kem_sk,
        &sender_sig_pk,
    )
    .expect_err("tampered tag must fail");
    assert!(err.to_string().contains("failed"));
}

#[test]
fn decrypt_rejects_tampered_signature() {
    let (recipient_kem_sk, sender_sig_pk, escrow_id, seq, mut sealed, msg_type) = setup_packet();
    let mut sig = B64.decode(sealed.sig_b64.as_bytes()).expect("decode sig");
    sig[0] ^= 0x02;
    sealed.sig_b64 = B64.encode(sig);

    decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &sealed,
        &recipient_kem_sk,
        &sender_sig_pk,
    )
    .expect_err("tampered signature must fail");
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let (recipient_kem_sk, sender_sig_pk, escrow_id, seq, mut sealed, msg_type) = setup_packet();
    let mut ct = B64
        .decode(sealed.ciphertext_b64.as_bytes())
        .expect("decode ciphertext");
    ct[0] ^= 0x04;
    sealed.ciphertext_b64 = B64.encode(ct);

    decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &sealed,
        &recipient_kem_sk,
        &sender_sig_pk,
    )
    .expect_err("tampered ciphertext must fail");
}

#[test]
fn decrypt_rejects_wrong_sender_key() {
    let (recipient_kem_sk, _sender_sig_pk, escrow_id, seq, sealed, msg_type) = setup_packet();
    let wrong_sender = Keys::generate().expect("wrong sender keys");
    let wrong_sender_pk = wrong_sender.sig_pk().expect("wrong sender pk");

    decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq,
        &sealed,
        &recipient_kem_sk,
        &wrong_sender_pk,
    )
    .expect_err("wrong sender key must fail");
}

#[test]
fn decrypt_rejects_wrong_seq() {
    let (recipient_kem_sk, sender_sig_pk, escrow_id, seq, sealed, msg_type) = setup_packet();

    decrypt(
        "alice",
        "bob",
        msg_type_key(&msg_type),
        &escrow_id,
        seq + 1,
        &sealed,
        &recipient_kem_sk,
        &sender_sig_pk,
    )
    .expect_err("wrong seq must fail");
}
