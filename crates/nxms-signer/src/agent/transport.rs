use super::*;

impl SignerAgent {
    pub(crate) async fn process_envelope(&self, env: NxmsEnvelope) -> Result<()> {
        env.validate_basic().map_err(|e| anyhow!(e))?;
        if env.to != self.cfg.local_id {
            return Err(anyhow!(
                "envelope addressed to '{}' but signer id is '{}'",
                env.to,
                self.cfg.local_id
            ));
        }
        if env.kem_id != suite_kem_id() || env.sig_id != suite_sig_id() {
            return Err(anyhow!("unexpected cipher suite ids"));
        }

        let peer = self
            .peers
            .get(&env.from)
            .ok_or_else(|| anyhow!("sender '{}' not in allowlist", env.from))?;
        let escrow_id_raw = decode_escrow_id_hex(&env.escrow_id_hex)?;

        let sealed = SealedPacket {
            kem_ct_b64: env.kem_ct_b64.clone(),
            nonce_b64: env.nonce_b64.clone(),
            ciphertext_b64: env.ciphertext_b64.clone(),
            tag_b64: env.tag_b64.clone(),
            sig_b64: env.sig_b64.clone(),
        };

        let peer_sig_pk = B64.decode(peer.sig_pk_b64.as_bytes())?;
        let self_kem_sk = self.keys.kem_sk_zeroizing()?;
        let plain = decrypt(
            &env.from,
            &env.to,
            msg_type_key(&env.msg_type),
            &escrow_id_raw,
            env.seq,
            &sealed,
            self_kem_sk.as_slice(),
            &peer_sig_pk,
        )?;
        let payload: NxmsPayload = serde_json::from_slice(&plain)?;
        payload
            .validate_matches_envelope(&env)
            .map_err(|e| anyhow!(e))?;

        let envelope_hash_hex = sha3_hex(&serde_json::to_vec(&env)?);
        let payload_hash_hex = sha3_hex(payload.data.as_bytes());

        if let Err(err) = self
            .db
            .record_incoming_seq(&payload.escrow_id_hex, &payload.from, payload.seq)
            .await
        {
            let detail = err.to_string();
            self.best_effort_audit(AuditLogInsert {
                event_kind: "rx_rejected_replay",
                escrow_id_hex: &payload.escrow_id_hex,
                from_id: Some(&payload.from),
                to_id: Some(&payload.to),
                seq: Some(payload.seq),
                envelope_hash_hex: Some(&envelope_hash_hex),
                payload_hash_hex: Some(&payload_hash_hex),
                decision: Some("rejected"),
                detail: Some(&detail),
            })
            .await;
            return Err(err);
        }

        self.best_effort_audit(AuditLogInsert {
            event_kind: "rx_validated",
            escrow_id_hex: &payload.escrow_id_hex,
            from_id: Some(&payload.from),
            to_id: Some(&payload.to),
            seq: Some(payload.seq),
            envelope_hash_hex: Some(&envelope_hash_hex),
            payload_hash_hex: Some(&payload_hash_hex),
            decision: None,
            detail: None,
        })
        .await;

        match payload.msg_type {
            MsgType::TxSignReq => {
                if let Err(err) = self.handle_tx_sign_req(&payload, &payload.data).await {
                    let detail = err.to_string();
                    self.best_effort_audit(AuditLogInsert {
                        event_kind: "tx_sign_req_rejected",
                        escrow_id_hex: &payload.escrow_id_hex,
                        from_id: Some(&payload.from),
                        to_id: Some(&payload.to),
                        seq: Some(payload.seq),
                        envelope_hash_hex: Some(&envelope_hash_hex),
                        payload_hash_hex: Some(&payload_hash_hex),
                        decision: Some("rejected"),
                        detail: Some(&detail),
                    })
                    .await;
                    return Err(err);
                }
            }
            _ => {
                self.send_body(
                    &payload.from,
                    &payload.escrow_id_hex,
                    MsgType::Error,
                    EscrowBody::Err(EscrowErrBody {
                        escrow_id_hex: payload.escrow_id_hex.clone(),
                        code: "unsupported_msg_type".to_string(),
                        reason: format!(
                            "manual signer supports only tx_sign_req, got {}",
                            msg_type_key(&payload.msg_type)
                        ),
                    }),
                )
                .await?;
                self.best_effort_audit(AuditLogInsert {
                    event_kind: "rx_unsupported_msg_type",
                    escrow_id_hex: &payload.escrow_id_hex,
                    from_id: Some(&payload.from),
                    to_id: Some(&payload.to),
                    seq: Some(payload.seq),
                    envelope_hash_hex: Some(&envelope_hash_hex),
                    payload_hash_hex: Some(&payload_hash_hex),
                    decision: Some("rejected"),
                    detail: Some("unsupported msg_type"),
                })
                .await;
            }
        }
        Ok(())
    }

    async fn handle_tx_sign_req(&self, payload: &NxmsPayload, body_raw: &str) -> Result<()> {
        let body: EscrowBody = serde_json::from_str(body_raw)?;
        let EscrowBody::TxSignReq(req) = body else {
            return Err(anyhow!("tx_sign_req payload kind mismatch"));
        };
        validate_tx_sign_req(payload, &req, self.cfg.max_txset_hex_len)?;

        let active = self
            .db
            .active_snapshot_for_escrow(&req.escrow_id_hex)
            .await?
            .ok_or_else(|| anyhow!("no active snapshot for escrow {}", req.escrow_id_hex))?;
        if !req
            .snapshot_hash_hex
            .trim()
            .eq_ignore_ascii_case(&active.hash_hex)
        {
            return Err(anyhow!(
                "tx_sign_req snapshot_hash mismatch: req={} active={}",
                req.snapshot_hash_hex,
                active.hash_hex
            ));
        }
        let snapshot: ContractSnapshot = serde_json::from_str(&active.snapshot_json)?;

        self.wallet.ensure_wallet_open().await?;
        let (check, raw_desc) = self
            .wallet
            .describe_transfer(&req.multisig_txset_hex)
            .await
            .map_err(|e| anyhow!("describe_transfer failed: {}", e))?;
        validate_transfer_against_snapshot(&snapshot, req.action.clone(), &check)?;

        let now_ms = now_ms();
        let describe_transfer_json = serde_json::to_string(&raw_desc)?;
        let txset_hash_hex = txset_sha256_hex(&req.multisig_txset_hex)?;
        let pending = PendingTxSign {
            id: 0,
            escrow_id_hex: req.escrow_id_hex.clone(),
            from_id: payload.from.clone(),
            to_id: payload.to.clone(),
            seq: payload.seq,
            action: serde_json::to_string(&req.action)?,
            snapshot_hash_hex: active.hash_hex,
            multisig_txset_hex: req.multisig_txset_hex.clone(),
            txset_hash_hex,
            describe_transfer_json,
            status: "pending".to_string(),
            decision_reason: None,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };
        self.db.enqueue_pending_tx(&pending).await?;
        self.best_effort_audit(AuditLogInsert {
            event_kind: "pending_enqueued",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&pending.from_id),
            to_id: Some(&pending.to_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&pending.txset_hash_hex),
            decision: Some("pending"),
            detail: Some("awaiting_manual_approval"),
        })
        .await;
        info!(
            "queued pending tx_sign_req escrow={} from={} seq={}",
            pending.escrow_id_hex, pending.from_id, pending.seq
        );
        Ok(())
    }

    pub(crate) async fn send_body(
        &self,
        to: &str,
        escrow_id_hex: &str,
        msg_type: MsgType,
        body: EscrowBody,
    ) -> Result<()> {
        let _ = self
            .send_body_with_seq(to, escrow_id_hex, msg_type, body, None)
            .await?;
        Ok(())
    }

    pub(crate) async fn send_body_with_seq(
        &self,
        to: &str,
        escrow_id_hex: &str,
        msg_type: MsgType,
        body: EscrowBody,
        seq_override: Option<u64>,
    ) -> Result<u64> {
        let peer = self
            .peers
            .get(to)
            .ok_or_else(|| anyhow!("peer '{}' not in allowlist", to))?;
        let escrow_id_raw = decode_escrow_id_hex(escrow_id_hex)?;
        let seq = match seq_override {
            Some(v) => v,
            None => {
                self.db
                    .next_out_seq(escrow_id_hex, &self.cfg.local_id)
                    .await?
            }
        };
        let payload = NxmsPayload {
            app_proto: ESCROW_APP_PROTO_V1.to_string(),
            msg_type: msg_type.clone(),
            escrow_id_hex: escrow_id_hex.to_string(),
            from: self.cfg.local_id.clone(),
            to: to.to_string(),
            seq,
            data: serde_json::to_string(&body)?,
        };
        let plain = serde_json::to_vec(&payload)?;

        let peer_kem_pk = B64.decode(peer.kem_pk_b64.as_bytes())?;
        let self_sig_sk = self.keys.sig_sk_zeroizing()?;
        let sealed = encrypt(
            &self.cfg.local_id,
            to,
            msg_type_key(&msg_type),
            &escrow_id_raw,
            seq,
            &peer_kem_pk,
            self_sig_sk.as_slice(),
            &plain,
        )?;

        let env = NxmsEnvelope {
            proto: "NXMS/1".to_string(),
            kem_id: suite_kem_id().to_string(),
            sig_id: suite_sig_id().to_string(),
            msg_type,
            escrow_id_hex: escrow_id_hex.to_string(),
            from: self.cfg.local_id.clone(),
            to: to.to_string(),
            seq,
            kem_ct_b64: sealed.kem_ct_b64,
            nonce_b64: sealed.nonce_b64,
            ciphertext_b64: sealed.ciphertext_b64,
            tag_b64: sealed.tag_b64,
            sig_b64: sealed.sig_b64,
        };
        let env_hash = sha3_hex(&serde_json::to_vec(&env)?);
        let payload_hash = sha3_hex(payload.data.as_bytes());

        let pushed = self
            .mailbox_push_with_retry(&env, Some(self.cfg.default_ttl_secs))
            .await?;
        self.best_effort_audit(AuditLogInsert {
            event_kind: "tx_sent",
            escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(to),
            seq: Some(seq),
            envelope_hash_hex: Some(&env_hash),
            payload_hash_hex: Some(&payload_hash),
            decision: Some("sent"),
            detail: None,
        })
        .await;
        debug!(
            "sent {} to {} escrow={} seq={} dedup={}",
            msg_type_key(&env.msg_type),
            to,
            escrow_id_hex,
            seq,
            pushed.dedup
        );
        Ok(seq)
    }

    pub(crate) async fn best_effort_audit(&self, event: AuditLogInsert<'_>) {
        if let Err(err) = self.db.append_audit_log(event).await {
            warn!("audit log append failed: {}", err);
        }
    }

    pub(crate) async fn mark_pending_error(&self, pending: &PendingTxSign, detail: &str) {
        if let Err(err) = self
            .db
            .set_pending_status(pending.id, "failed_dead_letter", Some(detail))
            .await
        {
            warn!(
                "failed to set pending dead-letter status for id {}: {}",
                pending.id, err
            );
        }
        self.best_effort_audit(AuditLogInsert {
            event_kind: "decision_error",
            escrow_id_hex: &pending.escrow_id_hex,
            from_id: Some(&self.cfg.local_id),
            to_id: Some(&pending.from_id),
            seq: Some(pending.seq),
            envelope_hash_hex: None,
            payload_hash_hex: Some(&pending.txset_hash_hex),
            decision: Some("dead_letter"),
            detail: Some(detail),
        })
        .await;
    }
}
