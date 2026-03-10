use sha3::{Digest, Keccak256};

const XMR_B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_value(ch: u8) -> Option<u8> {
    XMR_B58_ALPHABET
        .iter()
        .position(|v| *v == ch)
        .map(|idx| idx as u8)
}

fn decoded_block_size(encoded_len: usize) -> Option<usize> {
    match encoded_len {
        2 => Some(1),
        3 => Some(2),
        5 => Some(3),
        6 => Some(4),
        7 => Some(5),
        9 => Some(6),
        10 => Some(7),
        11 => Some(8),
        _ => None,
    }
}

fn decode_block(input: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut acc: u128 = 0;
    for ch in input {
        let digit = u128::from(b58_value(*ch)?);
        acc = acc.checked_mul(58)?.checked_add(digit)?;
        if acc > u128::from(u64::MAX) {
            return None;
        }
    }

    if out_len < 8 {
        let max_value = 1u128.checked_shl((out_len * 8) as u32)?;
        if acc >= max_value {
            return None;
        }
    }

    let mut out = vec![0u8; out_len];
    let value = acc as u64;
    for (idx, byte) in out.iter_mut().enumerate() {
        let shift = 8 * (out_len - 1 - idx);
        *byte = ((value >> shift) & 0xff) as u8;
    }
    Some(out)
}

fn decode_monero_base58(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }

    let full_blocks = input.len() / 11;
    let last_size = input.len() % 11;
    let last_decoded = if last_size == 0 {
        0
    } else {
        decoded_block_size(last_size)?
    };

    let mut out = Vec::with_capacity(full_blocks * 8 + last_decoded);
    for idx in 0..full_blocks {
        let start = idx * 11;
        let block = decode_block(&input[start..start + 11], 8)?;
        out.extend_from_slice(&block);
    }
    if last_size > 0 {
        let start = full_blocks * 11;
        let block = decode_block(&input[start..], last_decoded)?;
        out.extend_from_slice(&block);
    }
    Some(out)
}

fn valid_prefix_for_payload(prefix: u8, payload_len: usize) -> bool {
    match payload_len {
        // standard/subaddress: network byte + spend key + view key
        65 => matches!(prefix, 18 | 24 | 36 | 42 | 53 | 63),
        // integrated: network byte + spend key + view key + payment id
        73 => matches!(prefix, 19 | 25 | 54),
        _ => false,
    }
}

pub fn is_valid_xmr_address(addr: &str) -> bool {
    let trimmed = addr.trim();
    if !(trimmed.len() == 95 || trimmed.len() == 106) {
        return false;
    }
    if !trimmed.is_ascii() {
        return false;
    }

    let decoded = match decode_monero_base58(trimmed.as_bytes()) {
        Some(v) => v,
        None => return false,
    };
    if decoded.len() < 5 {
        return false;
    }

    let payload_len = decoded.len().saturating_sub(4);
    let payload = &decoded[..payload_len];
    let checksum = &decoded[payload_len..];
    if payload.is_empty() || !valid_prefix_for_payload(payload[0], payload.len()) {
        return false;
    }

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    checksum == &digest[..4]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_stagenet_address() {
        let addr = "572ycQUtcB2hKT8ivXBYCjfvS1QCWhYQpaYR9K1QPV6QQPrTugLpNDTByW72Nju7SL4RZd2UqhLaWWCWApR5Gfi8LGtUqsx";
        assert!(is_valid_xmr_address(addr));
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let bad = "572ycQUtcB2hKT8ivXBYCjfvS1QCWhYQpaYR9K1QPV6QQPrTugLpNDTByW72Nju7SL4RZd2UqhLaWWCWApR5Gfi8LGtUqsy";
        assert!(!is_valid_xmr_address(bad));
    }

    #[test]
    fn rejects_non_base58_and_wrong_len() {
        assert!(!is_valid_xmr_address("http://example.onion"));
        assert!(!is_valid_xmr_address("4".repeat(90).as_str()));
    }
}
