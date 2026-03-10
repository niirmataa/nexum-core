use zeroize::Zeroizing;

pub fn timing_safe_eq_fixed<const N: usize>(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() > N || bb.len() > N {
        return false;
    }

    let mut a_buf = Zeroizing::new([0u8; N]);
    let mut b_buf = Zeroizing::new([0u8; N]);
    a_buf[..ab.len()].copy_from_slice(ab);
    b_buf[..bb.len()].copy_from_slice(bb);

    let mut diff = ab.len() ^ bb.len();
    for idx in 0..N {
        diff |= usize::from(a_buf[idx] ^ b_buf[idx]);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::timing_safe_eq_fixed;

    #[test]
    fn timing_safe_eq_accepts_equal_values() {
        assert!(timing_safe_eq_fixed::<16>("abc", "abc"));
    }

    #[test]
    fn timing_safe_eq_rejects_mismatch() {
        assert!(!timing_safe_eq_fixed::<16>("abc", "abd"));
    }

    #[test]
    fn timing_safe_eq_rejects_too_long_input() {
        assert!(!timing_safe_eq_fixed::<3>("abcdef", "abcdef"));
    }
}
