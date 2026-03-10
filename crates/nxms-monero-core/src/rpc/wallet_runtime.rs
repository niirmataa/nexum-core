use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex as TokioMutex;
use tracing::warn;

use crate::crypto::multisig::MoneroMultisigEngine;
use crate::policy::{XMR_MULTISIG_ARBITER_INDEX, XMR_MULTISIG_THRESHOLD, XMR_MULTISIG_TOTAL};
use crate::rpc::wallet_rpc::{HttpWalletRpcClient, WalletRpcConfig};
use crate::types::{MoneroArbitraError, Result, WalletRpcError};

#[derive(Clone, Copy, Debug)]
struct WalletClientCacheConfig {
    max_entries: usize,
    max_age_s: i64,
}

#[derive(Clone)]
struct CachedClient {
    client: Arc<HttpWalletRpcClient>,
    last_used_ts: i64,
}

pub fn wallet_rpc_config(escrow_id: u64) -> Result<WalletRpcConfig> {
    let host = env::var("XMR_WALLET_RPC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = pick_port(escrow_id)?;
    let host = host.trim().trim_end_matches('/').to_string();
    if host.is_empty() {
        return Err(MoneroArbitraError::InvalidArgument(
            "XMR_WALLET_RPC_HOST must not be empty".to_string(),
        ));
    }
    if host.contains("://") {
        return Err(MoneroArbitraError::InvalidArgument(
            "XMR_WALLET_RPC_HOST must be host-only (without scheme)".to_string(),
        ));
    }
    let wallet_password = env::var("XMR_ARBITER_WALLET_PASS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            MoneroArbitraError::InvalidArgument(
                "XMR_ARBITER_WALLET_PASS must be set for Rust wallet-rpc runtime".to_string(),
            )
        })?;
    let username = env::var("XMR_WALLET_RPC_USER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            MoneroArbitraError::InvalidArgument(
                "XMR_WALLET_RPC_USER must be set for Rust wallet-rpc runtime".to_string(),
            )
        })?;
    let password = env::var("XMR_WALLET_RPC_PASS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            MoneroArbitraError::InvalidArgument(
                "XMR_WALLET_RPC_PASS must be set for Rust wallet-rpc runtime".to_string(),
            )
        })?;
    Ok(WalletRpcConfig {
        endpoint: format!("http://{host}:{port}"),
        wallet_name: format!("arb_escrow_{escrow_id}"),
        wallet_password,
        username,
        password,
        language: "English".to_string(),
        create_if_missing: true,
    })
}

pub fn pick_port(escrow_id: u64) -> Result<u16> {
    let pool = env::var("XMR_WALLET_RPC_POOL_PORTS").unwrap_or_default();
    if !pool.trim().is_empty() {
        let ports = pool
            .split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                p.parse::<u16>().map_err(|_| {
                    MoneroArbitraError::InvalidArgument(format!(
                        "invalid port in XMR_WALLET_RPC_POOL_PORTS: {p}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if ports.is_empty() {
            return Err(MoneroArbitraError::InvalidArgument(
                "XMR_WALLET_RPC_POOL_PORTS is empty".to_string(),
            ));
        }
        if wallet_pool_required() {
            ensure_wallet_pool_has_minimum_isolation(&ports)?;
        } else if unique_port_count(&ports) < 3 {
            warn!(
                "wallet-rpc pool has fewer than 3 unique ports; production should set XMR_WALLET_RPC_POOL_PORTS to at least 3 distinct ports"
            );
        }
        let idx = (escrow_id % (ports.len() as u64)) as usize;
        return Ok(ports[idx]);
    }

    if wallet_pool_required() {
        return Err(MoneroArbitraError::InvalidArgument(
            "XMR_WALLET_RPC_POOL_PORTS is required with at least 3 unique ports when production hardening is enabled".to_string(),
        ));
    }

    let single = env::var("XMR_WALLET_RPC_PORT").unwrap_or_else(|_| "18083".to_string());
    single.parse::<u16>().map_err(|_| {
        MoneroArbitraError::InvalidArgument(format!("invalid XMR_WALLET_RPC_PORT: {single}"))
    })
}

fn unique_port_count(ports: &[u16]) -> usize {
    ports.iter().copied().collect::<BTreeSet<u16>>().len()
}

fn ensure_wallet_pool_has_minimum_isolation(ports: &[u16]) -> Result<()> {
    let unique = unique_port_count(ports);
    if unique < 3 {
        return Err(MoneroArbitraError::InvalidArgument(format!(
            "XMR_WALLET_RPC_POOL_PORTS must contain at least 3 unique ports in production (got {unique})"
        )));
    }
    Ok(())
}

fn wallet_pool_required() -> bool {
    env_true("XMR_WALLET_RPC_POOL_REQUIRED")
        || (env_true("NXMS_ESCROW_HTTP_PRODUCTION_HARDENING") && !env_true("ESCROW_ALLOW_INSECURE"))
}

fn env_true(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn wallet_client_cache_config() -> WalletClientCacheConfig {
    static CONFIG: OnceLock<WalletClientCacheConfig> = OnceLock::new();
    *CONFIG.get_or_init(|| {
        let max_entries = env::var("XMR_WALLET_RPC_CLIENT_CACHE_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(20_000)
            .max(500);
        let max_age_s = env::var("XMR_WALLET_RPC_CLIENT_CACHE_MAX_AGE_S")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(6 * 3600)
            .max(60);
        WalletClientCacheConfig {
            max_entries,
            max_age_s,
        }
    })
}

fn prune_wallet_clients(clients: &mut BTreeMap<u64, CachedClient>, cfg: WalletClientCacheConfig) {
    if clients.len() <= cfg.max_entries {
        return;
    }

    let mut by_age: Vec<(u64, i64)> = clients
        .iter()
        .map(|(id, entry)| (*id, entry.last_used_ts))
        .collect();
    by_age.sort_by_key(|(_, ts)| *ts);
    let drop_n = clients.len().saturating_sub(cfg.max_entries);
    for (escrow_id, _) in by_age.into_iter().take(drop_n) {
        let _ = clients.remove(&escrow_id);
    }
}

fn wallet_client_store() -> &'static TokioMutex<BTreeMap<u64, CachedClient>> {
    static CLIENTS: OnceLock<TokioMutex<BTreeMap<u64, CachedClient>>> = OnceLock::new();
    CLIENTS.get_or_init(|| TokioMutex::new(BTreeMap::new()))
}

async fn wallet_client(escrow_id: u64) -> Result<Arc<HttpWalletRpcClient>> {
    // Intentionally keyed by escrow_id: the client currently carries wallet_name,
    // and sharing one client across escrows on the same endpoint could open the wrong wallet.
    let clients = wallet_client_store();

    let now = now_ts();
    let cfg = wallet_client_cache_config();
    let mut lock = clients.lock().await;

    // Always prune stale entries by TTL, even if we are below max_entries.
    let stale_before = now - cfg.max_age_s;
    lock.retain(|id, entry| *id == escrow_id || entry.last_used_ts >= stale_before);

    let cached = if let Some(existing) = lock.get_mut(&escrow_id) {
        existing.last_used_ts = now;
        Some(existing.client.clone())
    } else {
        None
    };
    prune_wallet_clients(&mut lock, cfg);
    if let Some(client) = cached {
        return Ok(client);
    }

    let client = Arc::new(HttpWalletRpcClient::new(wallet_rpc_config(escrow_id)?)?);
    lock.insert(
        escrow_id,
        CachedClient {
            client: client.clone(),
            last_used_ts: now,
        },
    );
    prune_wallet_clients(&mut lock, cfg);
    if let Some(existing) = lock.get(&escrow_id) {
        return Ok(existing.client.clone());
    }

    Ok(client)
}

async fn invalidate_wallet_client(escrow_id: u64) -> Result<()> {
    let clients = wallet_client_store();
    let mut lock = clients.lock().await;
    let _ = lock.remove(&escrow_id);
    Ok(())
}

async fn endpoint_mutex(endpoint: &str) -> Result<Arc<TokioMutex<()>>> {
    static LOCKS: OnceLock<TokioMutex<BTreeMap<String, Arc<TokioMutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| TokioMutex::new(BTreeMap::new()));
    let mut lock = locks.lock().await;
    if let Some(existing) = lock.get(endpoint) {
        return Ok(existing.clone());
    }
    let m = Arc::new(TokioMutex::new(()));
    lock.insert(endpoint.to_string(), m.clone());
    Ok(m)
}

#[derive(Clone, Copy, Debug)]
struct WalletCircuitConfig {
    fail_threshold: u32,
    open_secs: i64,
}

#[derive(Clone, Copy, Debug, Default)]
struct WalletCircuitState {
    consecutive_failures: u32,
    open_until_ts: i64,
}

fn wallet_circuit_config() -> WalletCircuitConfig {
    static CONFIG: OnceLock<WalletCircuitConfig> = OnceLock::new();
    *CONFIG.get_or_init(|| {
        let fail_threshold = env::var("XMR_WALLET_RPC_CB_FAIL_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(3);
        let open_secs = env::var("XMR_WALLET_RPC_CB_OPEN_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(20);
        WalletCircuitConfig {
            fail_threshold,
            open_secs,
        }
    })
}

fn wallet_circuit_store() -> &'static Mutex<BTreeMap<String, WalletCircuitState>> {
    static CIRCUITS: OnceLock<Mutex<BTreeMap<String, WalletCircuitState>>> = OnceLock::new();
    CIRCUITS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn wallet_circuit_before_call(endpoint: &str, op_name: &str) -> Result<()> {
    let now = now_ts();
    let lock = wallet_circuit_store().lock().map_err(|_| {
        MoneroArbitraError::InvalidArgument("wallet-rpc circuit cache poisoned".to_string())
    })?;
    if let Some(state) = lock.get(endpoint)
        && state.open_until_ts > now
    {
        let rem = state.open_until_ts - now;
        return Err(MoneroArbitraError::WalletRpc(WalletRpcError::Protocol(
            format!("wallet-rpc circuit open for endpoint {endpoint}; retry in {rem}s ({op_name})"),
        )));
    }
    Ok(())
}

fn wallet_circuit_record_success(endpoint: &str) -> Result<()> {
    let mut lock = wallet_circuit_store().lock().map_err(|_| {
        MoneroArbitraError::InvalidArgument("wallet-rpc circuit cache poisoned".to_string())
    })?;
    lock.remove(endpoint);
    Ok(())
}

fn wallet_circuit_record_failure(endpoint: &str, op_name: &str) -> Result<()> {
    let cfg = wallet_circuit_config();
    let now = now_ts();
    let mut lock = wallet_circuit_store().lock().map_err(|_| {
        MoneroArbitraError::InvalidArgument("wallet-rpc circuit cache poisoned".to_string())
    })?;
    let mut state = lock.get(endpoint).copied().unwrap_or_default();
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.consecutive_failures >= cfg.fail_threshold {
        state.consecutive_failures = 0;
        state.open_until_ts = now + cfg.open_secs;
        warn!(
            "wallet-rpc circuit opened for endpoint {} for {}s after {} failures ({})",
            endpoint, cfg.open_secs, cfg.fail_threshold, op_name
        );
    }
    lock.insert(endpoint.to_string(), state);
    Ok(())
}

fn should_trip_circuit(err: &MoneroArbitraError) -> bool {
    match err {
        MoneroArbitraError::Io(_) => true,
        MoneroArbitraError::WalletRpc(rpc_err) => {
            rpc_err.is_transient()
                || matches!(rpc_err, WalletRpcError::Protocol(msg) if {
                    let lower = msg.to_ascii_lowercase();
                    lower.contains("timed out") || lower.contains("timeout")
                })
        }
        _ => false,
    }
}

pub async fn wallet_rpc_call<T, F, Fut>(escrow_id: u64, op_name: &str, op: F) -> Result<T>
where
    F: FnOnce(MoneroMultisigEngine, Arc<HttpWalletRpcClient>) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let client = wallet_client(escrow_id).await?;
    client.ensure_wallet_open().await?;
    let endpoint = client.endpoint_key().to_string();

    // Fail fast without queueing behind endpoint mutex when circuit is open.
    wallet_circuit_before_call(&endpoint, op_name)?;

    let endpoint_lock = endpoint_mutex(&endpoint).await?;
    let _guard = endpoint_lock.lock().await;

    // Re-check after waiting for the lock: circuit state could have changed.
    wallet_circuit_before_call(&endpoint, op_name)?;
    let engine = MoneroMultisigEngine::new(
        XMR_MULTISIG_THRESHOLD,
        XMR_MULTISIG_TOTAL,
        XMR_MULTISIG_ARBITER_INDEX,
    )?;

    match op(engine, client).await {
        Ok(v) => {
            wallet_circuit_record_success(&endpoint)?;
            Ok(v)
        }
        Err(err) => {
            if let Err(cache_err) = invalidate_wallet_client(escrow_id).await {
                warn!(
                    "wallet-rpc client cache invalidate failed for escrow {}: {}",
                    escrow_id, cache_err
                );
            }
            if should_trip_circuit(&err) {
                wallet_circuit_record_failure(&endpoint, op_name)?;
            }
            Err(err)
        }
    }
}
