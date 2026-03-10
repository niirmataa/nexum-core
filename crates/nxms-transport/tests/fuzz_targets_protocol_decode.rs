use nxms_transport::wire::{EscrowBody, NxmsEnvelope, NxmsPayload};

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_bytes(seed: &mut u64, max_len: usize) -> Vec<u8> {
    let len = (xorshift64(seed) as usize) % max_len;
    let mut out = vec![0u8; len];
    for b in &mut out {
        *b = (xorshift64(seed) & 0xff) as u8;
    }
    out
}

fn mutate_bytes(seed: &mut u64, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    if out.is_empty() {
        return out;
    }
    let mutations = ((xorshift64(seed) % 7) + 1) as usize;
    for _ in 0..mutations {
        let idx = (xorshift64(seed) as usize) % out.len();
        out[idx] ^= (xorshift64(seed) & 0xff) as u8;
    }
    out
}

#[test]
fn fuzz_target_protocol_decode_smoke() {
    let mut seed: u64 = 0x91a7_42c1_d00d_beef;
    for _ in 0..1500 {
        let bytes = random_bytes(&mut seed, 1024);
        if let Ok(env) = serde_json::from_slice::<NxmsEnvelope>(&bytes) {
            let _ = env.validate_basic();
        }
        if let Ok(payload) = serde_json::from_slice::<NxmsPayload>(&bytes) {
            let _ = payload.validate_basic();
        }
        let _: Result<EscrowBody, _> = serde_json::from_slice(&bytes);
    }
}

#[test]
fn fuzz_target_protocol_decode_mutation_smoke() {
    let mut seed: u64 = 0x4ec3_7a2b_51d9_0001;
    let base = br#"{
      "proto":"NXMS/1",
      "kem_id":"FrodoKEM-640-SHAKE",
      "sig_id":"Falcon-1024-CT",
      "msg_type":"tx_sign_req",
      "escrow_id_hex":"00112233445566778899aabbccddeeff",
      "from":"peer_a",
      "to":"peer_b",
      "seq":7,
      "kem_ct_b64":"xx",
      "nonce_b64":"xx",
      "ciphertext_b64":"xx",
      "tag_b64":"xx",
      "sig_b64":"xx"
    }"#;
    for _ in 0..1000 {
        let mutated = mutate_bytes(&mut seed, base);
        if let Ok(env) = serde_json::from_slice::<NxmsEnvelope>(&mutated) {
            let _ = env.validate_basic();
        }
    }
}
