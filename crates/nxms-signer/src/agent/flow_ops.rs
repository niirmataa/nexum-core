use super::*;
use crate::orchestrator_bridge::{
    maybe_store_quorum_sign_proof, verify_submit_seller_quorum_proof,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignRequestCachedResult {
    op: String,
    #[serde(default)]
    tx_data_hex: Option<String>,
    #[serde(default)]
    tx_hash_list: Vec<String>,
}

impl SignerAgent {
    pub async fn sign_multisig_flow(
        &self,
        escrow_id_hex: &str,
        action: EscrowAction,
        tx_data_hex: &str,
        action_token: Option<&str>,
    ) -> Result<SignedMultisigTx> {
        let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
        let tx_data_hex = validate_tx_data_hex(tx_data_hex, self.cfg.max_txset_hex_len)?;
        let txset_hash_hex = txset_sha256_hex(&tx_data_hex)?;

        let active = self
            .db
            .active_snapshot_for_escrow(&escrow_id_hex)
            .await?
            .ok_or_else(|| anyhow!("no active snapshot for escrow {}", escrow_id_hex))?;
        let snapshot: ContractSnapshot = serde_json::from_str(&active.snapshot_json)?;
        let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot)?;
        if self.requires_escrow_admission() {
            self.validate_stored_escrow_admission(
                &escrow_id_hex,
                &snapshot_hash_for_token,
                action.clone(),
                None,
            )
            .await?;
        }

        self.wallet.ensure_wallet_open().await?;
        let (check, _) = self
            .wallet
            .describe_transfer(&tx_data_hex)
            .await
            .map_err(|e| anyhow!("describe_transfer failed during sign: {}", e))?;
        validate_transfer_against_snapshot(&snapshot, action.clone(), &check)?;

        let mut req_id_for_audit: Option<String> = None;
        let mut jti_for_audit: Option<String> = None;
        let mut exp_for_audit: Option<u64> = None;
        let mut sign_round_for_audit: String = default_sign_round(self.cfg.signer_role).to_string();
        let mut role_for_audit: String = signer_role_key(self.cfg.signer_role).to_string();

        if let Some(verifier) = &self.action_token_verifier {
            if let Some(action_token) = action_token {
                let verified = match verifier.verify_sign_multisig(
                    action_token,
                    &escrow_id_hex,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                ) {
                    Ok(v) => v,
                    Err(err) => {
                        let detail = audit_security_detail(
                            "sign_multisig",
                            &role_for_audit,
                            &sign_round_for_audit,
                            None,
                            &txset_hash_hex,
                            &snapshot_hash_for_token,
                            None,
                            None,
                            "reject",
                            Some(&err.to_string()),
                        );
                        self.best_effort_audit(AuditLogInsert {
                            event_kind: "sign_reject",
                            escrow_id_hex: &escrow_id_hex,
                            from_id: Some(&self.cfg.local_id),
                            to_id: None,
                            seq: None,
                            envelope_hash_hex: None,
                            payload_hash_hex: Some(&txset_hash_hex),
                            decision: Some("rejected"),
                            detail: Some(&detail),
                        })
                        .await;
                        return Err(err);
                    }
                };

                sign_round_for_audit = verified.claims.sign_round.clone();
                role_for_audit = verified.claims.role.clone();
                req_id_for_audit = Some(verified.req_id.clone());
                jti_for_audit = Some(verified.claims.jti.clone());
                exp_for_audit = Some(verified.claims.exp);
                if self.requires_escrow_admission() {
                    self.validate_stored_escrow_admission(
                        &escrow_id_hex,
                        &snapshot_hash_for_token,
                        action.clone(),
                        verified.claims.escrow_admission_hash.as_deref(),
                    )
                    .await?;
                }

                if let Err(err) = self
                    .db
                    .start_sign_request(
                        &verified.req_id,
                        &escrow_id_hex,
                        "sign_multisig",
                        &verified.claims.sign_round,
                        &txset_hash_hex,
                    )
                    .await
                {
                    if err.to_string().contains("duplicate req_id") {
                        let existing = self
                            .db
                            .get_sign_request(&verified.req_id)
                            .await?
                            .ok_or_else(|| {
                                anyhow!(
                                    "duplicate req_id {} reported but no request row found",
                                    verified.req_id
                                )
                            })?;
                        let metadata_match = existing.escrow_id_hex == escrow_id_hex
                            && existing.op == "sign_multisig"
                            && existing.sign_round == verified.claims.sign_round
                            && existing
                                .txset_hash_hex
                                .eq_ignore_ascii_case(&txset_hash_hex);
                        if !metadata_match {
                            let err = anyhow!(
                                "duplicate req_id {} has conflicting request metadata",
                                verified.req_id
                            );
                            let detail = audit_security_detail(
                                "sign_multisig",
                                &role_for_audit,
                                &sign_round_for_audit,
                                req_id_for_audit.as_deref(),
                                &txset_hash_hex,
                                &snapshot_hash_for_token,
                                jti_for_audit.as_deref(),
                                exp_for_audit,
                                "reject",
                                Some(&err.to_string()),
                            );
                            self.best_effort_audit(AuditLogInsert {
                                event_kind: "sign_reject",
                                escrow_id_hex: &escrow_id_hex,
                                from_id: Some(&self.cfg.local_id),
                                to_id: None,
                                seq: None,
                                envelope_hash_hex: None,
                                payload_hash_hex: Some(&txset_hash_hex),
                                decision: Some("rejected"),
                                detail: Some(&detail),
                            })
                            .await;
                            return Err(err);
                        }
                        if existing.status == "completed" {
                            if let Err(err) = self
                                .db
                                .consume_action_jti(
                                    &verified.claims.jti,
                                    &escrow_id_hex,
                                    "sign_multisig",
                                    &verified.claims.sign_round,
                                    &verified.req_id,
                                    verified.claims.exp,
                                )
                                .await
                            {
                                let detail = audit_security_detail(
                                    "sign_multisig",
                                    &role_for_audit,
                                    &sign_round_for_audit,
                                    req_id_for_audit.as_deref(),
                                    &txset_hash_hex,
                                    &snapshot_hash_for_token,
                                    jti_for_audit.as_deref(),
                                    exp_for_audit,
                                    "reject",
                                    Some(&err.to_string()),
                                );
                                self.best_effort_audit(AuditLogInsert {
                                    event_kind: "sign_reject",
                                    escrow_id_hex: &escrow_id_hex,
                                    from_id: Some(&self.cfg.local_id),
                                    to_id: None,
                                    seq: None,
                                    envelope_hash_hex: None,
                                    payload_hash_hex: Some(&txset_hash_hex),
                                    decision: Some("rejected"),
                                    detail: Some(&detail),
                                })
                                .await;
                                return Err(err);
                            }
                            let cached_json = self
                                .db
                                .get_sign_request_result(&verified.req_id)
                                .await?
                                .ok_or_else(|| {
                                    anyhow!(
                                        "duplicate req_id {} completed but cached result missing",
                                        verified.req_id
                                    )
                                })?;
                            let cached = parse_cached_sign_result(&cached_json)?;
                            let detail = audit_security_detail(
                                "sign_multisig",
                                &role_for_audit,
                                &sign_round_for_audit,
                                req_id_for_audit.as_deref(),
                                &txset_hash_hex,
                                &snapshot_hash_for_token,
                                jti_for_audit.as_deref(),
                                exp_for_audit,
                                "success",
                                Some("cached_replay"),
                            );
                            self.best_effort_audit(AuditLogInsert {
                                event_kind: "sign_success",
                                escrow_id_hex: &escrow_id_hex,
                                from_id: Some(&self.cfg.local_id),
                                to_id: None,
                                seq: None,
                                envelope_hash_hex: None,
                                payload_hash_hex: Some(&txset_hash_hex),
                                decision: Some("approved"),
                                detail: Some(&detail),
                            })
                            .await;
                            return Ok(cached);
                        }
                        let err = anyhow!("req_id {} already in progress", verified.req_id);
                        let detail = audit_security_detail(
                            "sign_multisig",
                            &role_for_audit,
                            &sign_round_for_audit,
                            req_id_for_audit.as_deref(),
                            &txset_hash_hex,
                            &snapshot_hash_for_token,
                            jti_for_audit.as_deref(),
                            exp_for_audit,
                            "reject",
                            Some(&err.to_string()),
                        );
                        self.best_effort_audit(AuditLogInsert {
                            event_kind: "sign_reject",
                            escrow_id_hex: &escrow_id_hex,
                            from_id: Some(&self.cfg.local_id),
                            to_id: None,
                            seq: None,
                            envelope_hash_hex: None,
                            payload_hash_hex: Some(&txset_hash_hex),
                            decision: Some("rejected"),
                            detail: Some(&detail),
                        })
                        .await;
                        return Err(err);
                    }
                    let detail = audit_security_detail(
                        "sign_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "sign_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }

                if let Err(err) = self
                    .db
                    .consume_action_jti(
                        &verified.claims.jti,
                        &escrow_id_hex,
                        "sign_multisig",
                        &verified.claims.sign_round,
                        &verified.req_id,
                        verified.claims.exp,
                    )
                    .await
                {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let detail = audit_security_detail(
                        "sign_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "sign_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
            } else if verifier.is_required() {
                let err = anyhow!("action token required for sign in current signer configuration");
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            } else {
                let err = anyhow!("action token required for sign in current signer configuration");
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            }
        }

        let sign_attempt_detail = audit_security_detail(
            "sign_multisig",
            &role_for_audit,
            &sign_round_for_audit,
            req_id_for_audit.as_deref(),
            &txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "attempt",
            None,
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "sign_attempt",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: Some(&txset_hash_hex),
            decision: Some("attempt"),
            detail: Some(&sign_attempt_detail),
        })
        .await;

        let signed = match self.wallet.sign_multisig(&tx_data_hex).await {
            Ok(v) => v,
            Err(err) => {
                if let Some(req_id) = req_id_for_audit.as_deref() {
                    let _ = self.db.abort_sign_request(req_id).await;
                }
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    req_id_for_audit.as_deref(),
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    jti_for_audit.as_deref(),
                    exp_for_audit,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            }
        };
        if let Some(req_id) = req_id_for_audit.as_deref() {
            let cached_json = serialize_sign_cached_result(&signed)?;
            self.db
                .complete_sign_request_with_result(req_id, "sign_multisig", &cached_json)
                .await?;
        }
        if let (Some(jti), Some(req_id)) = (jti_for_audit.as_deref(), req_id_for_audit.as_deref()) {
            self.db
                .record_sign_event(
                    &escrow_id_hex,
                    &role_for_audit,
                    &sign_round_for_audit,
                    &txset_hash_hex,
                    jti,
                    req_id,
                )
                .await?;
            maybe_store_quorum_sign_proof(
                &escrow_id_hex,
                &role_for_audit,
                &sign_round_for_audit,
                &txset_hash_hex,
                jti,
                req_id,
            )
            .await?;
        }
        let sign_success_detail = audit_security_detail(
            "sign_multisig",
            &role_for_audit,
            &sign_round_for_audit,
            req_id_for_audit.as_deref(),
            &txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "success",
            Some(&format!("tx_hashes={}", signed.tx_hash_list.join(","))),
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "sign_success",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: Some(&txset_hash_hex),
            decision: Some("approved"),
            detail: Some(&sign_success_detail),
        })
        .await;
        Ok(signed)
    }

    pub async fn propose_multisig_flow(
        &self,
        escrow_id_hex: &str,
        action: EscrowAction,
        amount_override_atomic: Option<u64>,
    ) -> Result<ProposedMultisigTx> {
        let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
        let active = self
            .db
            .active_snapshot_for_escrow(&escrow_id_hex)
            .await?
            .ok_or_else(|| anyhow!("no active snapshot for escrow {}", escrow_id_hex))?;
        let snapshot: ContractSnapshot = serde_json::from_str(&active.snapshot_json)?;
        let recipients =
            proposal_recipients_from_snapshot(&snapshot, action.clone(), amount_override_atomic)?;
        let action_dbg = format!("{:?}", action);

        let recipients_detail = recipients
            .iter()
            .map(|r| format!("{}:{}", r.address, r.amount))
            .collect::<Vec<_>>()
            .join(",");
        self.best_effort_audit(AuditLogInsert {
            event_kind: "proposal_attempt",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: None,
            decision: Some("attempt"),
            detail: Some(&format!(
                "action={} recipients={}",
                action_dbg, recipients_detail
            )),
        })
        .await;

        self.wallet.ensure_wallet_open().await?;
        let tx_data_hex = self
            .wallet
            .transfer_multisig_do_not_relay(&recipients)
            .await
            .map_err(|e| anyhow!("transfer do_not_relay failed during proposal: {}", e))?;
        let tx_data_hex = validate_tx_data_hex(&tx_data_hex, self.cfg.max_txset_hex_len)?;
        let txset_hash_hex = txset_sha256_hex(&tx_data_hex)?;

        let (check, _) = self
            .wallet
            .describe_transfer(&tx_data_hex)
            .await
            .map_err(|e| anyhow!("describe_transfer failed during proposal: {}", e))?;
        validate_transfer_against_snapshot(&snapshot, action.clone(), &check)?;

        self.best_effort_audit(AuditLogInsert {
            event_kind: "proposal_success",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: Some(&txset_hash_hex),
            decision: Some("success"),
            detail: Some(&format!("action={}", action_dbg)),
        })
        .await;

        Ok(ProposedMultisigTx {
            tx_data_hex,
            txset_hash_hex,
        })
    }

    pub async fn submit_multisig_flow(
        &self,
        escrow_id_hex: &str,
        action: EscrowAction,
        tx_data_hex: &str,
        action_token: Option<&str>,
    ) -> Result<Vec<String>> {
        let escrow_id_hex = normalize_hex_exact(escrow_id_hex, 32, "escrow_id_hex")?;
        let tx_data_hex = validate_tx_data_hex(tx_data_hex, self.cfg.max_txset_hex_len)?;
        let txset_hash_hex = txset_sha256_hex(&tx_data_hex)?;

        let active = self
            .db
            .active_snapshot_for_escrow(&escrow_id_hex)
            .await?
            .ok_or_else(|| anyhow!("no active snapshot for escrow {}", escrow_id_hex))?;
        let snapshot: ContractSnapshot = serde_json::from_str(&active.snapshot_json)?;
        let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot)?;
        if self.requires_escrow_admission() {
            self.validate_stored_escrow_admission(
                &escrow_id_hex,
                &snapshot_hash_for_token,
                action.clone(),
                None,
            )
            .await?;
        }

        self.wallet.ensure_wallet_open().await?;
        let (check, _) = self
            .wallet
            .describe_transfer(&tx_data_hex)
            .await
            .map_err(|e| anyhow!("describe_transfer failed during submit: {}", e))?;
        validate_transfer_against_snapshot(&snapshot, action.clone(), &check)?;

        let mut req_id_for_audit: Option<String> = None;
        let mut jti_for_audit: Option<String> = None;
        let mut exp_for_audit: Option<u64> = None;
        let mut sign_round_for_audit: String =
            default_submit_round(self.cfg.signer_role).to_string();
        let mut role_for_audit: String = signer_role_key(self.cfg.signer_role).to_string();

        if let Some(verifier) = &self.action_token_verifier {
            if let Some(action_token) = action_token {
                let verified = match verifier.verify_submit_multisig(
                    action_token,
                    &escrow_id_hex,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                ) {
                    Ok(v) => v,
                    Err(err) => {
                        let detail = audit_security_detail(
                            "submit_multisig",
                            &role_for_audit,
                            &sign_round_for_audit,
                            None,
                            &txset_hash_hex,
                            &snapshot_hash_for_token,
                            None,
                            None,
                            "reject",
                            Some(&err.to_string()),
                        );
                        self.best_effort_audit(AuditLogInsert {
                            event_kind: "submit_reject",
                            escrow_id_hex: &escrow_id_hex,
                            from_id: Some(&self.cfg.local_id),
                            to_id: None,
                            seq: None,
                            envelope_hash_hex: None,
                            payload_hash_hex: Some(&txset_hash_hex),
                            decision: Some("rejected"),
                            detail: Some(&detail),
                        })
                        .await;
                        return Err(err);
                    }
                };

                sign_round_for_audit = verified.claims.sign_round.clone();
                role_for_audit = verified.claims.role.clone();
                req_id_for_audit = Some(verified.req_id.clone());
                jti_for_audit = Some(verified.claims.jti.clone());
                exp_for_audit = Some(verified.claims.exp);
                if self.requires_escrow_admission() {
                    self.validate_stored_escrow_admission(
                        &escrow_id_hex,
                        &snapshot_hash_for_token,
                        action.clone(),
                        verified.claims.escrow_admission_hash.as_deref(),
                    )
                    .await?;
                }

                if let Err(err) = self
                    .db
                    .start_sign_request(
                        &verified.req_id,
                        &escrow_id_hex,
                        "submit_multisig",
                        &verified.claims.sign_round,
                        &txset_hash_hex,
                    )
                    .await
                {
                    if err.to_string().contains("duplicate req_id") {
                        let existing = self
                            .db
                            .get_sign_request(&verified.req_id)
                            .await?
                            .ok_or_else(|| {
                                anyhow!(
                                    "duplicate req_id {} reported but no request row found",
                                    verified.req_id
                                )
                            })?;
                        let metadata_match = existing.escrow_id_hex == escrow_id_hex
                            && existing.op == "submit_multisig"
                            && existing.sign_round == verified.claims.sign_round
                            && existing
                                .txset_hash_hex
                                .eq_ignore_ascii_case(&txset_hash_hex);
                        if !metadata_match {
                            let err = anyhow!(
                                "duplicate req_id {} has conflicting request metadata",
                                verified.req_id
                            );
                            let detail = audit_security_detail(
                                "submit_multisig",
                                &role_for_audit,
                                &sign_round_for_audit,
                                req_id_for_audit.as_deref(),
                                &txset_hash_hex,
                                &snapshot_hash_for_token,
                                jti_for_audit.as_deref(),
                                exp_for_audit,
                                "reject",
                                Some(&err.to_string()),
                            );
                            self.best_effort_audit(AuditLogInsert {
                                event_kind: "submit_reject",
                                escrow_id_hex: &escrow_id_hex,
                                from_id: Some(&self.cfg.local_id),
                                to_id: None,
                                seq: None,
                                envelope_hash_hex: None,
                                payload_hash_hex: Some(&txset_hash_hex),
                                decision: Some("rejected"),
                                detail: Some(&detail),
                            })
                            .await;
                            return Err(err);
                        }
                        if existing.status == "completed" {
                            if let Err(err) = self
                                .db
                                .consume_action_jti(
                                    &verified.claims.jti,
                                    &escrow_id_hex,
                                    "submit_multisig",
                                    &verified.claims.sign_round,
                                    &verified.req_id,
                                    verified.claims.exp,
                                )
                                .await
                            {
                                let detail = audit_security_detail(
                                    "submit_multisig",
                                    &role_for_audit,
                                    &sign_round_for_audit,
                                    req_id_for_audit.as_deref(),
                                    &txset_hash_hex,
                                    &snapshot_hash_for_token,
                                    jti_for_audit.as_deref(),
                                    exp_for_audit,
                                    "reject",
                                    Some(&err.to_string()),
                                );
                                self.best_effort_audit(AuditLogInsert {
                                    event_kind: "submit_reject",
                                    escrow_id_hex: &escrow_id_hex,
                                    from_id: Some(&self.cfg.local_id),
                                    to_id: None,
                                    seq: None,
                                    envelope_hash_hex: None,
                                    payload_hash_hex: Some(&txset_hash_hex),
                                    decision: Some("rejected"),
                                    detail: Some(&detail),
                                })
                                .await;
                                return Err(err);
                            }
                            let cached_json = self
                                .db
                                .get_sign_request_result(&verified.req_id)
                                .await?
                                .ok_or_else(|| {
                                    anyhow!(
                                        "duplicate req_id {} completed but cached result missing",
                                        verified.req_id
                                    )
                                })?;
                            let cached = parse_cached_submit_result(&cached_json)?;
                            let detail = audit_security_detail(
                                "submit_multisig",
                                &role_for_audit,
                                &sign_round_for_audit,
                                req_id_for_audit.as_deref(),
                                &txset_hash_hex,
                                &snapshot_hash_for_token,
                                jti_for_audit.as_deref(),
                                exp_for_audit,
                                "success",
                                Some("cached_replay"),
                            );
                            self.best_effort_audit(AuditLogInsert {
                                event_kind: "submit_success",
                                escrow_id_hex: &escrow_id_hex,
                                from_id: Some(&self.cfg.local_id),
                                to_id: None,
                                seq: None,
                                envelope_hash_hex: None,
                                payload_hash_hex: Some(&txset_hash_hex),
                                decision: Some("submitted"),
                                detail: Some(&detail),
                            })
                            .await;
                            return Ok(cached);
                        }
                        let err = anyhow!("req_id {} already in progress", verified.req_id);
                        let detail = audit_security_detail(
                            "submit_multisig",
                            &role_for_audit,
                            &sign_round_for_audit,
                            req_id_for_audit.as_deref(),
                            &txset_hash_hex,
                            &snapshot_hash_for_token,
                            jti_for_audit.as_deref(),
                            exp_for_audit,
                            "reject",
                            Some(&err.to_string()),
                        );
                        self.best_effort_audit(AuditLogInsert {
                            event_kind: "submit_reject",
                            escrow_id_hex: &escrow_id_hex,
                            from_id: Some(&self.cfg.local_id),
                            to_id: None,
                            seq: None,
                            envelope_hash_hex: None,
                            payload_hash_hex: Some(&txset_hash_hex),
                            decision: Some("rejected"),
                            detail: Some(&detail),
                        })
                        .await;
                        return Err(err);
                    }
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }

                if let Err(err) = self
                    .db
                    .consume_action_jti(
                        &verified.claims.jti,
                        &escrow_id_hex,
                        "submit_multisig",
                        &verified.claims.sign_round,
                        &verified.req_id,
                        verified.claims.exp,
                    )
                    .await
                {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }

                // Require local proof of arbiter first signature and exact match
                // against token-embedded arbiter proof tuple (jti + req_id).
                let local_arbiter_proof = self
                    .db
                    .get_sign_event(&escrow_id_hex, "arbiter", "arbiter_first", &txset_hash_hex)
                    .await?;
                let Some(local_arbiter_proof) = local_arbiter_proof else {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let err =
                        anyhow!("submit denied: missing local quorum proof event arbiter_first");
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                };

                let token_arbiter_jti = verified
                    .claims
                    .proof_arbiter_jti
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| anyhow!("submit denied: missing proof_arbiter_jti"))?;
                let token_arbiter_req_id = verified
                    .claims
                    .proof_arbiter_req_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| anyhow!("submit denied: missing proof_arbiter_req_id"))?;
                if local_arbiter_proof.jti != token_arbiter_jti
                    || local_arbiter_proof.req_id != token_arbiter_req_id
                {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let err = anyhow!(
                        "submit denied: local arbiter quorum proof mismatch (token vs signer db)"
                    );
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
                if verified
                    .claims
                    .proof_seller_jti
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let err = anyhow!("submit denied: missing seller quorum proof in action token");
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
                let token_seller_req_id = verified
                    .claims
                    .proof_seller_req_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty());
                let Some(token_seller_req_id) = token_seller_req_id else {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let err = anyhow!(
                        "submit denied: missing seller req_id quorum proof in action token"
                    );
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                };
                let token_seller_jti = verified
                    .claims
                    .proof_seller_jti
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty());
                let Some(token_seller_jti) = token_seller_jti else {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let err = anyhow!("submit denied: missing seller quorum proof in action token");
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                };
                if let Err(err) = verify_submit_seller_quorum_proof(
                    &escrow_id_hex,
                    &txset_hash_hex,
                    token_seller_jti,
                    token_seller_req_id,
                    self.cfg.production_hardening,
                )
                .await
                {
                    let _ = self.db.abort_sign_request(&verified.req_id).await;
                    let detail = audit_security_detail(
                        "submit_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "submit_reject",
                        escrow_id_hex: &escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: None,
                        seq: None,
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
            } else if verifier.is_required() {
                let err =
                    anyhow!("action token required for submit in current signer configuration");
                let detail = audit_security_detail(
                    "submit_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "submit_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            } else {
                let err =
                    anyhow!("action token required for submit in current signer configuration");
                let detail = audit_security_detail(
                    "submit_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "submit_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            }
        }

        let submit_attempt_detail = audit_security_detail(
            "submit_multisig",
            &role_for_audit,
            &sign_round_for_audit,
            req_id_for_audit.as_deref(),
            &txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "attempt",
            None,
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "submit_attempt",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: Some(&txset_hash_hex),
            decision: Some("attempt"),
            detail: Some(&submit_attempt_detail),
        })
        .await;

        let tx_hash_list = match self.wallet.submit_multisig(&tx_data_hex).await {
            Ok(v) => v,
            Err(err) => {
                if let Some(req_id) = req_id_for_audit.as_deref() {
                    let _ = self.db.abort_sign_request(req_id).await;
                }
                let detail = audit_security_detail(
                    "submit_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    req_id_for_audit.as_deref(),
                    &txset_hash_hex,
                    &snapshot_hash_for_token,
                    jti_for_audit.as_deref(),
                    exp_for_audit,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "submit_reject",
                    escrow_id_hex: &escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: None,
                    seq: None,
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            }
        };
        if let Some(req_id) = req_id_for_audit.as_deref() {
            let cached_json = serialize_submit_cached_result(&tx_hash_list)?;
            self.db
                .complete_sign_request_with_result(req_id, "submit_multisig", &cached_json)
                .await?;
        }

        let detail = audit_security_detail(
            "submit_multisig",
            &role_for_audit,
            &sign_round_for_audit,
            req_id_for_audit.as_deref(),
            &txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "success",
            Some(&format!("tx_hashes={}", tx_hash_list.join(","))),
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "submit_success",
            escrow_id_hex: &escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: None,
            seq: None,
            envelope_hash_hex: None,
            payload_hash_hex: Some(&txset_hash_hex),
            decision: Some("submitted"),
            detail: Some(&detail),
        })
        .await;
        Ok(tx_hash_list)
    }
}

fn serialize_sign_cached_result(signed: &SignedMultisigTx) -> Result<String> {
    let payload = SignRequestCachedResult {
        op: "sign_multisig".to_string(),
        tx_data_hex: Some(signed.tx_data_hex.clone()),
        tx_hash_list: signed.tx_hash_list.clone(),
    };
    Ok(serde_json::to_string(&payload)?)
}

fn serialize_submit_cached_result(tx_hash_list: &[String]) -> Result<String> {
    let payload = SignRequestCachedResult {
        op: "submit_multisig".to_string(),
        tx_data_hex: None,
        tx_hash_list: tx_hash_list.to_vec(),
    };
    Ok(serde_json::to_string(&payload)?)
}

fn parse_cached_sign_result(raw: &str) -> Result<SignedMultisigTx> {
    let parsed: SignRequestCachedResult = serde_json::from_str(raw)?;
    if parsed.op != "sign_multisig" {
        return Err(anyhow!(
            "cached result op mismatch for sign_multisig: {}",
            parsed.op
        ));
    }
    let tx_data_hex = parsed
        .tx_data_hex
        .ok_or_else(|| anyhow!("cached sign result missing tx_data_hex"))?;
    if tx_data_hex.trim().is_empty() {
        return Err(anyhow!("cached sign result has empty tx_data_hex"));
    }
    Ok(SignedMultisigTx {
        tx_data_hex,
        tx_hash_list: parsed.tx_hash_list,
    })
}

fn parse_cached_submit_result(raw: &str) -> Result<Vec<String>> {
    let parsed: SignRequestCachedResult = serde_json::from_str(raw)?;
    if parsed.op != "submit_multisig" {
        return Err(anyhow!(
            "cached result op mismatch for submit_multisig: {}",
            parsed.op
        ));
    }
    Ok(parsed.tx_hash_list)
}
