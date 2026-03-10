use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApprovedSendState {
    signed_tx_data_hex: String,
    #[serde(default)]
    tx_hash_list: Vec<String>,
    #[serde(default)]
    out_seq: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RejectedSendState {
    reason: String,
    #[serde(default)]
    out_seq: Option<u64>,
}

impl SignerAgent {
    pub async fn approve_pending(&self, id: i64, action_token: Option<&str>) -> Result<()> {
        let pending = self
            .db
            .get_pending(id)
            .await?
            .ok_or_else(|| anyhow!("pending id {} not found", id))?;
        if pending.status == "approved_sending" {
            let staged = parse_approved_send_state(id, pending.decision_reason.as_deref())?;
            let body = EscrowBody::TxSignResp(TxSignRespBody {
                escrow_id_hex: pending.escrow_id_hex.clone(),
                approved: true,
                signed_tx_data_hex: Some(staged.signed_tx_data_hex.clone()),
                tx_hash_list: staged.tx_hash_list.clone(),
                reason: None,
            });
            match staged.out_seq {
                Some(out_seq) => {
                    let _ = self
                        .send_body_with_seq(
                            &pending.from_id,
                            &pending.escrow_id_hex,
                            MsgType::TxSignResp,
                            body,
                            Some(out_seq),
                        )
                        .await?;
                }
                None => {
                    self.send_body(
                        &pending.from_id,
                        &pending.escrow_id_hex,
                        MsgType::TxSignResp,
                        body,
                    )
                    .await?;
                }
            }
            self.db
                .set_pending_status(id, "approved_sent", None)
                .await?;
            self.best_effort_audit(AuditLogInsert {
                event_kind: "decision_approved",
                escrow_id_hex: &pending.escrow_id_hex,
                from_id: Some(&self.cfg.local_id),
                to_id: Some(&pending.from_id),
                seq: Some(pending.seq),
                envelope_hash_hex: None,
                payload_hash_hex: Some(&pending.txset_hash_hex),
                decision: Some("approved"),
                detail: Some("retry_send_from_staged_state"),
            })
            .await;
            return Ok(());
        }
        if pending.status != "pending" {
            return Err(anyhow!(
                "pending id {} has status '{}', expected 'pending' or 'approved_sending'",
                id,
                pending.status
            ));
        }

        let computed_txset_hash_hex = txset_sha256_hex(&pending.multisig_txset_hex)?;
        if !computed_txset_hash_hex.eq_ignore_ascii_case(&pending.txset_hash_hex) {
            // Keep backward compatibility for rows created before txset hash migration.
            let legacy_txset_hash_hex = sha3_hex(pending.multisig_txset_hex.as_bytes());
            if legacy_txset_hash_hex.eq_ignore_ascii_case(&pending.txset_hash_hex) {
                warn!(
                    "pending_id={} uses legacy sha3 txset hash; requeue with sha256 for strict mode",
                    pending.id
                );
            } else {
                let detail = format!(
                    "txset hash mismatch for pending_id={}: computed_sha256={} stored={}",
                    pending.id, computed_txset_hash_hex, pending.txset_hash_hex
                );
                self.mark_pending_error(&pending, &detail).await;
                return Err(anyhow!(detail));
            }
        }

        let pending_snapshot_hash =
            normalize_hex_exact(&pending.snapshot_hash_hex, 64, "pending.snapshot_hash_hex")?;
        let active = self
            .db
            .active_snapshot_for_escrow(&pending.escrow_id_hex)
            .await?
            .ok_or_else(|| anyhow!("no active snapshot for escrow {}", pending.escrow_id_hex))?;
        if !pending_snapshot_hash.eq_ignore_ascii_case(&active.hash_hex) {
            let detail = format!(
                "pending snapshot mismatch for pending_id={}: pending={} active={}",
                pending.id, pending_snapshot_hash, active.hash_hex
            );
            self.mark_pending_error(&pending, &detail).await;
            return Err(anyhow!(detail));
        }

        let snapshot: ContractSnapshot = serde_json::from_str(&active.snapshot_json)?;
        let snapshot_hash_for_token = canonical_policy_hash_sha256_hex(&snapshot)?;
        let action = parse_pending_action(&pending.action)?;
        self.wallet.ensure_wallet_open().await?;
        let (check, _) = self
            .wallet
            .describe_transfer(&pending.multisig_txset_hex)
            .await
            .map_err(|e| anyhow!("describe_transfer failed during approval: {}", e))?;
        if let Err(err) = validate_transfer_against_snapshot(&snapshot, action, &check) {
            let detail = format!(
                "policy check failed during approval for pending_id={}: {}",
                pending.id, err
            );
            self.mark_pending_error(&pending, &detail).await;
            return Err(anyhow!(detail));
        }

        let mut req_id_for_audit: Option<String> = None;
        let mut jti_for_audit: Option<String> = None;
        let mut exp_for_audit: Option<u64> = None;
        let mut sign_round_for_audit: String = default_sign_round(self.cfg.signer_role).to_string();
        let mut role_for_audit: String = signer_role_key(self.cfg.signer_role).to_string();
        if let Some(verifier) = &self.action_token_verifier {
            if let Some(action_token) = action_token {
                let verified = match verifier.verify_sign_multisig(
                    action_token,
                    &pending.escrow_id_hex,
                    &computed_txset_hash_hex,
                    &snapshot_hash_for_token,
                ) {
                    Ok(v) => v,
                    Err(err) => {
                        let detail = audit_security_detail(
                            "sign_multisig",
                            &role_for_audit,
                            &sign_round_for_audit,
                            None,
                            &computed_txset_hash_hex,
                            &snapshot_hash_for_token,
                            None,
                            None,
                            "reject",
                            Some(&err.to_string()),
                        );
                        self.best_effort_audit(AuditLogInsert {
                            event_kind: "sign_reject",
                            escrow_id_hex: &pending.escrow_id_hex,
                            from_id: Some(&self.cfg.local_id),
                            to_id: Some(&pending.from_id),
                            seq: Some(pending.seq),
                            envelope_hash_hex: None,
                            payload_hash_hex: Some(&computed_txset_hash_hex),
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

                if let Err(err) = self
                    .db
                    .start_sign_request(
                        &verified.req_id,
                        &pending.escrow_id_hex,
                        "sign_multisig",
                        &verified.claims.sign_round,
                        &computed_txset_hash_hex,
                    )
                    .await
                {
                    let detail = audit_security_detail(
                        "sign_multisig",
                        &role_for_audit,
                        &sign_round_for_audit,
                        req_id_for_audit.as_deref(),
                        &computed_txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "sign_reject",
                        escrow_id_hex: &pending.escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: Some(&pending.from_id),
                        seq: Some(pending.seq),
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&computed_txset_hash_hex),
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
                        &pending.escrow_id_hex,
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
                        &computed_txset_hash_hex,
                        &snapshot_hash_for_token,
                        jti_for_audit.as_deref(),
                        exp_for_audit,
                        "reject",
                        Some(&err.to_string()),
                    );
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "sign_reject",
                        escrow_id_hex: &pending.escrow_id_hex,
                        from_id: Some(&self.cfg.local_id),
                        to_id: Some(&pending.from_id),
                        seq: Some(pending.seq),
                        envelope_hash_hex: None,
                        payload_hash_hex: Some(&computed_txset_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
            } else if verifier.is_required() {
                let err =
                    anyhow!("action token required for approve in current signer configuration");
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &computed_txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_reject",
                    escrow_id_hex: &pending.escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: Some(&pending.from_id),
                    seq: Some(pending.seq),
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&computed_txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            } else {
                warn!(
                    "approve pending_id={} without action token (shadow mode)",
                    pending.id
                );
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    None,
                    &computed_txset_hash_hex,
                    &snapshot_hash_for_token,
                    None,
                    None,
                    "shadow_allow",
                    Some("action token missing during approve_pending; shadow mode allowed"),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_shadow_allow",
                    escrow_id_hex: &pending.escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: Some(&pending.from_id),
                    seq: Some(pending.seq),
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&computed_txset_hash_hex),
                    decision: Some("shadow_allow"),
                    detail: Some(&detail),
                })
                .await;
            }
        }

        let sign_attempt_detail = audit_security_detail(
            "sign_multisig",
            &role_for_audit,
            &sign_round_for_audit,
            req_id_for_audit.as_deref(),
            &computed_txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "attempt",
            None,
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "sign_attempt",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(&pending.from_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&computed_txset_hash_hex),
            decision: Some("attempt"),
            detail: Some(&sign_attempt_detail),
        })
        .await;

        let signed = match self.wallet.sign_multisig(&pending.multisig_txset_hex).await {
            Ok(signed) => signed,
            Err(err) => {
                if let Some(req_id) = req_id_for_audit.as_deref() {
                    let _ = self.db.abort_sign_request(req_id).await;
                }
                let detail = audit_security_detail(
                    "sign_multisig",
                    &role_for_audit,
                    &sign_round_for_audit,
                    req_id_for_audit.as_deref(),
                    &computed_txset_hash_hex,
                    &snapshot_hash_for_token,
                    jti_for_audit.as_deref(),
                    exp_for_audit,
                    "reject",
                    Some(&err.to_string()),
                );
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "sign_reject",
                    escrow_id_hex: &pending.escrow_id_hex,
                    from_id: Some(&self.cfg.local_id),
                    to_id: Some(&pending.from_id),
                    seq: Some(pending.seq),
                    envelope_hash_hex: None,
                    payload_hash_hex: Some(&computed_txset_hash_hex),
                    decision: Some("rejected"),
                    detail: Some(&detail),
                })
                .await;
                return Err(err);
            }
        };
        if let Some(req_id) = req_id_for_audit.as_deref() {
            let cached_json = serde_json::to_string(&serde_json::json!({
                "op": "sign_multisig",
                "tx_data_hex": signed.tx_data_hex.clone(),
                "tx_hash_list": signed.tx_hash_list.clone(),
            }))?;
            self.db
                .complete_sign_request_with_result(req_id, "sign_multisig", &cached_json)
                .await?;
        }
        if let (Some(jti), Some(req_id)) = (jti_for_audit.as_deref(), req_id_for_audit.as_deref()) {
            self.db
                .record_sign_event(
                    &pending.escrow_id_hex,
                    &role_for_audit,
                    &sign_round_for_audit,
                    &computed_txset_hash_hex,
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
            &computed_txset_hash_hex,
            &snapshot_hash_for_token,
            jti_for_audit.as_deref(),
            exp_for_audit,
            "success",
            Some(&format!("tx_hashes={}", signed.tx_hash_list.join(","))),
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "sign_success",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(&pending.from_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&computed_txset_hash_hex),
            decision: Some("approved"),
            detail: Some(&sign_success_detail),
        })
        .await;

        let body = EscrowBody::TxSignResp(TxSignRespBody {
            escrow_id_hex: pending.escrow_id_hex.clone(),
            approved: true,
            signed_tx_data_hex: Some(signed.tx_data_hex.clone()),
            tx_hash_list: signed.tx_hash_list.clone(),
            reason: None,
        });
        let staged = ApprovedSendState {
            signed_tx_data_hex: signed.tx_data_hex,
            tx_hash_list: signed.tx_hash_list,
            out_seq: Some(
                self.db
                    .next_out_seq(&pending.escrow_id_hex, &self.cfg.local_id)
                    .await?,
            ),
        };
        let staged_json = serde_json::to_string(&staged)?;
        // Persist signed response before outbound send; if mailbox send fails,
        // retry can resume from `approved_sending` without re-signing.
        self.db
            .set_pending_status(id, "approved_sending", Some(&staged_json))
            .await?;
        let _ = self
            .send_body_with_seq(
                &pending.from_id,
                &pending.escrow_id_hex,
                MsgType::TxSignResp,
                body,
                staged.out_seq,
            )
            .await?;
        self.db
            .set_pending_status(id, "approved_sent", None)
            .await?;
        let detail = format!(
            "pending_id={id} req_id={} sign_round={} role={} jti={} exp={}",
            req_id_for_audit.as_deref().unwrap_or("-"),
            sign_round_for_audit.as_str(),
            role_for_audit.as_str(),
            jti_for_audit.as_deref().unwrap_or("-"),
            exp_for_audit
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        self.best_effort_audit(AuditLogInsert {
            event_kind: "decision_approved",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(&pending.from_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&pending.txset_hash_hex),
            decision: Some("approved"),
            detail: Some(&detail),
        })
        .await;
        Ok(())
    }

    pub async fn reject_pending(&self, id: i64, reason: &str) -> Result<()> {
        let pending = self
            .db
            .get_pending(id)
            .await?
            .ok_or_else(|| anyhow!("pending id {} not found", id))?;
        if pending.status == "rejected_sending" {
            let staged = parse_rejected_send_state(id, pending.decision_reason.as_deref())?;
            let body = EscrowBody::Err(EscrowErrBody {
                escrow_id_hex: pending.escrow_id_hex.clone(),
                code: "tx_sign_rejected".to_string(),
                reason: staged.reason.clone(),
            });
            match staged.out_seq {
                Some(out_seq) => {
                    let _ = self
                        .send_body_with_seq(
                            &pending.from_id,
                            &pending.escrow_id_hex,
                            MsgType::Error,
                            body,
                            Some(out_seq),
                        )
                        .await?;
                }
                None => {
                    self.send_body(
                        &pending.from_id,
                        &pending.escrow_id_hex,
                        MsgType::Error,
                        body,
                    )
                    .await?;
                }
            }
            self.db
                .set_pending_status(id, "rejected", Some(&staged.reason))
                .await?;
            self.best_effort_audit(AuditLogInsert {
                event_kind: "decision_rejected",
                escrow_id_hex: &pending.escrow_id_hex,
                from_id: Some(&self.cfg.local_id),
                to_id: Some(&pending.from_id),
                seq: Some(pending.seq),
                envelope_hash_hex: None,
                payload_hash_hex: Some(&pending.txset_hash_hex),
                decision: Some("rejected"),
                detail: Some("retry_send_from_staged_state"),
            })
            .await;
            return Ok(());
        }
        if pending.status != "pending" {
            return Err(anyhow!(
                "pending id {} has status '{}', expected 'pending' or 'rejected_sending'",
                id,
                pending.status
            ));
        }

        let staged = RejectedSendState {
            reason: reason.to_string(),
            out_seq: Some(
                self.db
                    .next_out_seq(&pending.escrow_id_hex, &self.cfg.local_id)
                    .await?,
            ),
        };
        let staged_json = serde_json::to_string(&staged)?;
        self.db
            .set_pending_status(id, "rejected_sending", Some(&staged_json))
            .await?;

        let body = EscrowBody::Err(EscrowErrBody {
            escrow_id_hex: pending.escrow_id_hex.clone(),
            code: "tx_sign_rejected".to_string(),
            reason: reason.to_string(),
        });
        let _ = self
            .send_body_with_seq(
                &pending.from_id,
                &pending.escrow_id_hex,
                MsgType::Error,
                body,
                staged.out_seq,
            )
            .await?;
        self.db
            .set_pending_status(id, "rejected", Some(reason))
            .await?;
        self.best_effort_audit(AuditLogInsert {
            event_kind: "decision_rejected",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(&pending.from_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&pending.txset_hash_hex),
            decision: Some("rejected"),
            detail: Some(reason),
        })
        .await;
        Ok(())
    }
}

fn parse_approved_send_state(id: i64, raw: Option<&str>) -> Result<ApprovedSendState> {
    let raw = raw.ok_or_else(|| {
        anyhow!(
            "pending id {} has status approved_sending but missing staged send payload",
            id
        )
    })?;
    let staged: ApprovedSendState = serde_json::from_str(raw).map_err(|e| {
        anyhow!(
            "pending id {} has invalid staged send payload for approved_sending: {}",
            id,
            e
        )
    })?;
    if staged.signed_tx_data_hex.trim().is_empty() {
        return Err(anyhow!(
            "pending id {} has empty signed_tx_data_hex in staged send payload",
            id
        ));
    }
    Ok(staged)
}

fn parse_rejected_send_state(id: i64, raw: Option<&str>) -> Result<RejectedSendState> {
    let raw = raw.ok_or_else(|| {
        anyhow!(
            "pending id {} has status rejected_sending but missing staged send payload",
            id
        )
    })?;
    let staged: RejectedSendState = serde_json::from_str(raw).map_err(|e| {
        anyhow!(
            "pending id {} has invalid staged send payload for rejected_sending: {}",
            id,
            e
        )
    })?;
    if staged.reason.trim().is_empty() {
        return Err(anyhow!(
            "pending id {} has empty reject reason in staged send payload",
            id
        ));
    }
    Ok(staged)
}
