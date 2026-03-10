use crate::db::{OrchestratorDb, WorkflowInstance};
use crate::flow::WorkflowState;
use crate::wallet::{
    ConfirmationState, WalletRpcClient, WalletRpcConfig, evaluate_confirmation, evaluate_preflight,
};
use anyhow::{Result, anyhow};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    pub stage_timeout_ms: u64,
    pub submit_timeout_ms: u64,
    pub funded_min_balance: u64,
    pub funded_min_unlocked_balance: u64,
    pub max_height_lag: u64,
    pub tx_sign_quorum: u64,
    pub confirm_required: u64,
    pub batch_limit: u32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TickReport {
    pub scanned: u64,
    pub transitioned: u64,
    pub dead_lettered: u64,
    pub confirmed: u64,
}

#[derive(Clone)]
pub struct OrchestratorWorker {
    db: OrchestratorDb,
    wallet: Option<WalletRpcClient>,
    cfg: WorkerConfig,
}

impl WorkerConfig {
    pub fn from_run_args(
        stage_timeout_ms: u64,
        submit_timeout_ms: u64,
        funded_min_balance: u64,
        funded_min_unlocked_balance: u64,
        max_height_lag: u64,
        tx_sign_quorum: u64,
        confirm_required: u64,
        batch_limit: u32,
    ) -> Self {
        Self {
            stage_timeout_ms: stage_timeout_ms.max(1_000),
            submit_timeout_ms: submit_timeout_ms.max(1_000),
            funded_min_balance,
            funded_min_unlocked_balance,
            max_height_lag,
            tx_sign_quorum: tx_sign_quorum.max(1),
            confirm_required: confirm_required.max(1),
            batch_limit: batch_limit.max(1).min(5000),
        }
    }
}

impl OrchestratorWorker {
    pub fn new(db: OrchestratorDb, wallet: Option<WalletRpcClient>, cfg: WorkerConfig) -> Self {
        Self { db, wallet, cfg }
    }

    pub fn wallet_from_env() -> Option<WalletRpcClient> {
        let endpoint = std::env::var("NXMS_WALLET_RPC_ENDPOINT")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;
        let wallet_name = std::env::var("NXMS_WALLET_RPC_WALLET_NAME")
            .ok()
            .unwrap_or_else(|| "nxms_orchestrator_wallet".to_string());
        let wallet_password = std::env::var("NXMS_WALLET_RPC_WALLET_PASSWORD")
            .ok()
            .unwrap_or_default();
        let username = std::env::var("NXMS_WALLET_RPC_USERNAME")
            .ok()
            .unwrap_or_default();
        let password = std::env::var("NXMS_WALLET_RPC_PASSWORD")
            .ok()
            .unwrap_or_default();
        Some(WalletRpcClient::new(WalletRpcConfig {
            endpoint,
            wallet_name,
            wallet_password,
            username,
            password,
        }))
    }

    pub async fn tick_once(&self) -> Result<TickReport> {
        let mut report = TickReport::default();
        let workflows = self.db.list_workflows(self.cfg.batch_limit).await?;
        for wf in workflows {
            if matches!(
                wf.state,
                WorkflowState::Confirmed | WorkflowState::FailedDeadLetter
            ) {
                continue;
            }
            report.scanned = report.scanned.saturating_add(1);

            if self.is_timeout_exhausted(&wf) {
                self.compensate_dead_letter(
                    &wf,
                    "worker_tick",
                    "timeout_exhausted",
                    "workflow state timeout exceeded",
                )
                .await;
                report.dead_lettered = report.dead_lettered.saturating_add(1);
                continue;
            }

            match self.handle_state(&wf).await {
                Ok(StateOutcome::Noop) => {}
                Ok(StateOutcome::Transitioned) => {
                    report.transitioned = report.transitioned.saturating_add(1);
                }
                Ok(StateOutcome::Confirmed) => {
                    report.confirmed = report.confirmed.saturating_add(1);
                }
                Err(err) => {
                    // Treat worker errors as retriable unless timeout policy exhausts.
                    warn!(
                        "worker state handling error escrow={} state={:?}: {}",
                        wf.escrow_id_hex, wf.state, err
                    );
                }
            }
        }
        Ok(report)
    }

    fn is_timeout_exhausted(&self, wf: &WorkflowInstance) -> bool {
        let now = now_ms();
        let age = now.saturating_sub(wf.updated_at_ms);
        let threshold = if wf.state == WorkflowState::Submitted {
            self.cfg.submit_timeout_ms
        } else {
            self.cfg.stage_timeout_ms
        };
        age > threshold
    }

    async fn handle_state(&self, wf: &WorkflowInstance) -> Result<StateOutcome> {
        let expected = wf.participants.len() as u64;
        match wf.state {
            WorkflowState::New => {
                self.transition_if_count_ready(wf, WorkflowState::PrepareCollected, expected)
                    .await
            }
            WorkflowState::PrepareCollected => {
                self.transition_if_count_ready(wf, WorkflowState::MakeCollected, expected)
                    .await
            }
            WorkflowState::MakeCollected => {
                self.transition_if_count_ready(wf, WorkflowState::ExchangeR1Collected, expected)
                    .await
            }
            WorkflowState::ExchangeR1Collected => {
                self.transition_if_count_ready(wf, WorkflowState::ExchangeR2Collected, expected)
                    .await
            }
            WorkflowState::ExchangeR2Collected => {
                self.require_wallet_preflight(0, 0).await?;
                self.db
                    .transition_workflow(&wf.escrow_id_hex, WorkflowState::FinalizedReady, None)
                    .await?;
                Ok(StateOutcome::Transitioned)
            }
            WorkflowState::FinalizedReady => {
                self.require_wallet_preflight(
                    self.cfg.funded_min_balance,
                    self.cfg.funded_min_unlocked_balance,
                )
                .await?;
                self.db
                    .transition_workflow(&wf.escrow_id_hex, WorkflowState::Funded, None)
                    .await?;
                Ok(StateOutcome::Transitioned)
            }
            WorkflowState::Funded => {
                self.transition_if_count_ready(wf, WorkflowState::TxSignPending, 1)
                    .await
            }
            WorkflowState::TxSignPending => {
                self.transition_if_count_ready(
                    wf,
                    WorkflowState::TxSignedQuorum,
                    self.cfg.tx_sign_quorum,
                )
                .await
            }
            WorkflowState::TxSignedQuorum => {
                let watch = self.db.get_submission_watch(&wf.escrow_id_hex).await?;
                if let Some(watch) = watch
                    && watch.status == "pending"
                {
                    self.db
                        .transition_workflow(&wf.escrow_id_hex, WorkflowState::Submitted, None)
                        .await?;
                    return Ok(StateOutcome::Transitioned);
                }
                Ok(StateOutcome::Noop)
            }
            WorkflowState::Submitted => {
                let watch = self
                    .db
                    .get_submission_watch(&wf.escrow_id_hex)
                    .await?
                    .ok_or_else(|| anyhow!("missing submission watch"))?;
                if watch.status == "confirmed" {
                    self.db
                        .transition_workflow(&wf.escrow_id_hex, WorkflowState::Confirmed, None)
                        .await?;
                    return Ok(StateOutcome::Confirmed);
                }
                if watch.status == "failed" {
                    self.compensate_dead_letter(
                        wf,
                        "submit_watch",
                        "watch_failed",
                        "submission watch status=failed",
                    )
                    .await;
                    return Ok(StateOutcome::Noop);
                }
                let wallet = self
                    .wallet
                    .as_ref()
                    .ok_or_else(|| anyhow!("wallet-rpc not configured"))?;
                let status = wallet.transfer_status(&watch.txid).await?;
                let required_confirmations =
                    watch.required_confirmations.max(self.cfg.confirm_required);
                match evaluate_confirmation(&status, required_confirmations) {
                    ConfirmationState::Pending => {
                        self.db
                            .update_submission_watch_progress(
                                &wf.escrow_id_hex,
                                "pending",
                                status.confirmations,
                                false,
                            )
                            .await?;
                        debug!(
                            "pending confirmations escrow={} txid={} conf={}",
                            wf.escrow_id_hex, status.txid, status.confirmations
                        );
                        Ok(StateOutcome::Noop)
                    }
                    ConfirmationState::Confirmed => {
                        self.db
                            .update_submission_watch_progress(
                                &wf.escrow_id_hex,
                                "confirmed",
                                status.confirmations,
                                false,
                            )
                            .await?;
                        self.db
                            .transition_workflow(&wf.escrow_id_hex, WorkflowState::Confirmed, None)
                            .await?;
                        Ok(StateOutcome::Confirmed)
                    }
                    ConfirmationState::FailedDoubleSpend => {
                        self.db
                            .update_submission_watch_progress(
                                &wf.escrow_id_hex,
                                "failed",
                                status.confirmations,
                                true,
                            )
                            .await?;
                        self.compensate_dead_letter(
                            wf,
                            "submit_watch",
                            "double_spend_seen",
                            "double spend observed while watching confirmations",
                        )
                        .await;
                        Ok(StateOutcome::Noop)
                    }
                }
            }
            WorkflowState::Confirmed | WorkflowState::FailedDeadLetter => Ok(StateOutcome::Noop),
        }
    }

    async fn transition_if_count_ready(
        &self,
        wf: &WorkflowInstance,
        to_state: WorkflowState,
        expected_count: u64,
    ) -> Result<StateOutcome> {
        let count = self
            .db
            .step_count_for_state(&wf.escrow_id_hex, to_state)
            .await?;
        if count >= expected_count {
            self.db
                .transition_workflow(&wf.escrow_id_hex, to_state, None)
                .await?;
            return Ok(StateOutcome::Transitioned);
        }
        Ok(StateOutcome::Noop)
    }

    async fn require_wallet_preflight(
        &self,
        min_balance: u64,
        min_unlocked_balance: u64,
    ) -> Result<()> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("wallet-rpc not configured"))?;
        let health = wallet.health_snapshot().await?;
        evaluate_preflight(
            &health,
            min_balance,
            min_unlocked_balance,
            self.cfg.max_height_lag,
        )?;
        Ok(())
    }

    async fn compensate_dead_letter(
        &self,
        wf: &WorkflowInstance,
        stage: &str,
        error_code: &str,
        detail: &str,
    ) {
        if let Err(err) = self
            .db
            .add_dead_letter(&wf.escrow_id_hex, stage, error_code, detail, 1, None)
            .await
        {
            warn!(
                "failed to add dead-letter escrow={} stage={}: {}",
                wf.escrow_id_hex, stage, err
            );
        }
        if let Err(err) = self
            .db
            .transition_workflow(
                &wf.escrow_id_hex,
                WorkflowState::FailedDeadLetter,
                Some(detail),
            )
            .await
        {
            warn!(
                "failed to transition to dead-letter escrow={} stage={}: {}",
                wf.escrow_id_hex, stage, err
            );
        } else {
            info!(
                "workflow moved to dead-letter escrow={} stage={} code={}",
                wf.escrow_id_hex, stage, error_code
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StateOutcome {
    Noop,
    Transitioned,
    Confirmed,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{OrchestratorDb, StepInput};

    fn unique_db_path(label: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nxms_worker_test_{label}_{}_{}.db",
            std::process::id(),
            ts
        ))
    }

    fn worker_cfg() -> WorkerConfig {
        WorkerConfig::from_run_args(120_000, 120_000, 0, 0, 100, 2, 2, 100)
    }

    #[tokio::test]
    async fn tick_transitions_new_to_prepare_when_all_steps_exist() {
        let db_path = unique_db_path("new_to_prepare");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["alice".to_string(), "bob".to_string()],
        )
        .await
        .expect("create");
        db.record_step(StepInput {
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            state: WorkflowState::PrepareCollected,
            from_id: "alice".to_string(),
            seq: 1,
            msg_type: "prepare_info".to_string(),
            payload_hash_hex: "11".repeat(32),
        })
        .await
        .expect("step1");
        db.record_step(StepInput {
            escrow_id_hex: "00112233445566778899aabbccddeeff".to_string(),
            state: WorkflowState::PrepareCollected,
            from_id: "bob".to_string(),
            seq: 1,
            msg_type: "prepare_info".to_string(),
            payload_hash_hex: "22".repeat(32),
        })
        .await
        .expect("step2");

        let worker = OrchestratorWorker::new(db.clone(), None, worker_cfg());
        let report = worker.tick_once().await.expect("tick");
        assert_eq!(report.transitioned, 1);
        let wf = db
            .get_workflow("00112233445566778899aabbccddeeff")
            .await
            .expect("wf")
            .expect("wf exists");
        assert_eq!(wf.state, WorkflowState::PrepareCollected);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn tick_deadletters_timed_out_workflow() {
        let db_path = unique_db_path("timeout_deadletter");
        let db = OrchestratorDb::new(db_path.clone());
        db.init().await.expect("init");
        db.create_workflow(
            "00112233445566778899aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["alice".to_string()],
        )
        .await
        .expect("create");

        let worker = OrchestratorWorker::new(
            db.clone(),
            None,
            WorkerConfig {
                stage_timeout_ms: 1,
                submit_timeout_ms: 1,
                funded_min_balance: 0,
                funded_min_unlocked_balance: 0,
                max_height_lag: 100,
                tx_sign_quorum: 2,
                confirm_required: 2,
                batch_limit: 100,
            },
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
        let report = worker.tick_once().await.expect("tick");
        assert_eq!(report.dead_lettered, 1);
        let wf = db
            .get_workflow("00112233445566778899aabbccddeeff")
            .await
            .expect("wf")
            .expect("wf exists");
        assert_eq!(wf.state, WorkflowState::FailedDeadLetter);
        let _ = std::fs::remove_file(db_path);
    }
}
