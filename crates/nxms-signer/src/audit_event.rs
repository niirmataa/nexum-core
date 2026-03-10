use anyhow::{Result, anyhow};

pub const CHALLENGE_ISSUED: &str = "challenge_issued";
pub const CHALLENGE_VERIFIED: &str = "challenge_verified";
pub const TOKEN_ISSUED: &str = "token_issued";
pub const SIGN_SHADOW_ALLOW: &str = "sign_shadow_allow";
pub const SUBMIT_SHADOW_ALLOW: &str = "submit_shadow_allow";

const KNOWN_EVENT_KINDS: &[&str] = &[
    CHALLENGE_ISSUED,
    CHALLENGE_VERIFIED,
    TOKEN_ISSUED,
    "rx_rejected_replay",
    "rx_validated",
    "tx_sign_req_rejected",
    "rx_unsupported_msg_type",
    "pending_enqueued",
    "tx_sent",
    "decision_error",
    "decision_approved",
    "decision_rejected",
    "proposal_attempt",
    "proposal_success",
    "sign_attempt",
    "sign_reject",
    "sign_success",
    SIGN_SHADOW_ALLOW,
    "submit_attempt",
    "submit_reject",
    "submit_success",
    SUBMIT_SHADOW_ALLOW,
];

pub fn normalize_auth_event_kind(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        CHALLENGE_ISSUED => Ok(CHALLENGE_ISSUED),
        CHALLENGE_VERIFIED => Ok(CHALLENGE_VERIFIED),
        TOKEN_ISSUED => Ok(TOKEN_ISSUED),
        _ => Err(anyhow!(
            "auth event kind must be one of: challenge_issued|challenge_verified|token_issued"
        )),
    }
}

pub fn validate_known_audit_event_kind(event_kind: &str) -> Result<()> {
    if KNOWN_EVENT_KINDS.iter().any(|v| *v == event_kind) {
        return Ok(());
    }
    Err(anyhow!("unknown audit event kind '{}'", event_kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_auth_event_kind_accepts_known_values_case_insensitive() {
        assert_eq!(
            normalize_auth_event_kind(" challenge_issued ").expect("challenge"),
            CHALLENGE_ISSUED
        );
        assert_eq!(
            normalize_auth_event_kind("CHALLENGE_VERIFIED").expect("verified"),
            CHALLENGE_VERIFIED
        );
        assert_eq!(
            normalize_auth_event_kind("Token_Issued").expect("issued"),
            TOKEN_ISSUED
        );
    }

    #[test]
    fn validate_known_audit_event_kind_rejects_unknown_value() {
        let err = validate_known_audit_event_kind("weird_event_kind")
            .expect_err("unknown kind must reject");
        assert!(err.to_string().contains("unknown audit event kind"));
    }
}
