use std::env;
use std::sync::OnceLock;

const DEFAULT_TX_HEX_MAX_LEN: usize = 2_000_000;
const MIN_TX_HEX_MAX_LEN: usize = 200_000;
const MAX_TX_HEX_MAX_LEN: usize = 20_000_000;

pub fn tx_hex_max_len() -> usize {
    static TX_HEX_MAX: OnceLock<usize> = OnceLock::new();
    *TX_HEX_MAX.get_or_init(|| {
        let raw = env::var("XMR_TX_HEX_MAX_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TX_HEX_MAX_LEN);
        raw.clamp(MIN_TX_HEX_MAX_LEN, MAX_TX_HEX_MAX_LEN)
    })
}
