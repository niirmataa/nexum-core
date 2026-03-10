use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type WalletId = String;
pub type PeerId = String;
pub type AccountIndex = u32;
pub type SubaddressIndex = u32;
pub type TxId = String;
pub type KeyImage = [u8; 32];
pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];
pub type Hash = [u8; 32];
pub type Commitment = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneroAddress {
    pub spend_public: PublicKey,
    pub view_public: PublicKey,
    pub network: Network,
}

impl MoneroAddress {
    pub fn encode(&self) -> String {
        let net = match self.network {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Stagenet => "stagenet",
        };
        format!(
            "xmr:{net}:{}:{}",
            hex::encode(self.spend_public),
            hex::encode(self.view_public)
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 || parts[0] != "xmr" {
            return Err(MoneroArbitraError::InvalidAddress(
                "expected xmr:<network>:<spend_hex>:<view_hex>".to_string(),
            ));
        }

        let network = match parts[1] {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            "stagenet" => Network::Stagenet,
            _ => {
                return Err(MoneroArbitraError::InvalidAddress(
                    "unknown network".to_string(),
                ));
            }
        };

        let spend = decode_32(parts[2]).map_err(MoneroArbitraError::InvalidAddress)?;
        let view = decode_32(parts[3]).map_err(MoneroArbitraError::InvalidAddress)?;

        Ok(Self {
            spend_public: spend,
            view_public: view,
            network,
        })
    }
}

impl fmt::Display for MoneroAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl FromStr for MoneroAddress {
    type Err = MoneroArbitraError;

    fn from_str(s: &str) -> Result<Self> {
        Self::decode(s)
    }
}

fn decode_32(s: &str) -> std::result::Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("key must be 32 bytes".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigKeySet {
    pub account_index: AccountIndex,
    pub spend_secret: Option<SecretKey>,
    pub view_secret: SecretKey,
    pub multisig_spend_public: PublicKey,
    pub multisig_view_public: PublicKey,
    pub round_keys: MultisigRounds,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MultisigRounds {
    pub round1: HashMap<PeerId, Round1Data>,
    pub round2: HashMap<PeerId, Round2Data>,
    pub round3: HashMap<PeerId, Round3Data>,
    pub completed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Data {
    pub peer_id: PeerId,
    pub pubkeys: Vec<PublicKey>,
    pub base_multisig_info: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Data {
    pub peer_id: PeerId,
    pub dh_shared_secrets: Vec<PublicKey>,
    pub partial_privkeys: Vec<SecretKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Data {
    pub peer_id: PeerId,
    pub partial_key_images: Vec<PartialKeyImage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialKeyImage {
    pub output_index: u32,
    pub key_image: KeyImage,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigPolicy {
    pub threshold: u16,
    pub total_signers: u16,
    pub signers: Vec<SignerInfo>,
    pub creation_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerInfo {
    pub peer_id: PeerId,
    pub label: String,
    pub round1_pubkey: PublicKey,
    pub is_me: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroOutput {
    pub amount: u64,
    pub commitment: Commitment,
    pub stealth_address: PublicKey,
    pub tx_pub_key: PublicKey,
    pub output_index: u32,
    pub global_index: u64,
    pub key_image: Option<KeyImage>,
    pub unlock_time: u64,
    pub spent: bool,
    pub spent_in_tx: Option<TxId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroTransaction {
    pub tx_id: TxId,
    pub wallet_id: WalletId,
    pub status: TxStatus,
    pub inputs: Vec<MoneroInput>,
    pub outputs: Vec<MoneroOutput>,
    pub signing_state: MultisigSigningState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroInput {
    pub output: MoneroOutput,
    pub key_image: KeyImage,
    pub ring_members: Vec<PublicKey>,
    pub real_output_index: u8,
    pub mlsag_signature: Option<MlsagSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsagSignature {
    pub c0: SecretKey,
    pub s: Vec<SecretKey>,
    pub key_image: KeyImage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigSigningState {
    pub stage: SigningStage,
    pub signers_responded: HashMap<PeerId, SignerRound>,
    pub tx_unsigned: Vec<u8>,
    pub tx_signed_hash: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningStage {
    AwaitingParticipants,
    Round0,
    Round1,
    Round2,
    ReadyToSubmit,
    Submitted,
    Confirmed(u64),
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerRound {
    pub peer_id: PeerId,
    pub round0_data: Option<Round0Signing>,
    pub round1_data: Option<Round1Signing>,
    pub round2_data: Option<Round2Signing>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round0Signing {
    pub key_images: Vec<KeyImage>,
    pub output_proofs: Vec<OutputProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Signing {
    pub alpha_commitments: Vec<PublicKey>,
    pub c0_share: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Signing {
    pub partial_sig: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputProof {
    pub output_index: u32,
    pub shared_secret: PublicKey,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EscrowState {
    New,
    XmrMsigR1,
    XmrMsigR2,
    XmrMsigR3,
    Ready,
    Funded,
    Released,
    Refunded,
    Dispute,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Asset {
    Xmr,
    Btc,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EscrowParticipant {
    Buyer,
    Seller,
    Arbiter,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Draft,
    PendingSignatures,
    ReadyToBroadcast,
    Broadcast,
    Confirmed(u64),
    Failed(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WalletRpcError {
    #[error("transport: {0}")]
    Transport(String),

    #[error("http status {status}: {body}")]
    HttpStatus { status: u16, body: String },

    #[error("rpc code={code}, message={message}")]
    Rpc { code: i64, message: String },

    #[error("auth: {0}")]
    Auth(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl WalletRpcError {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::HttpStatus { status, .. } => *status >= 500 || *status == 429 || *status == 408,
            Self::Rpc { .. } | Self::Auth(_) | Self::Protocol(_) | Self::InvalidResponse(_) => {
                false
            }
        }
    }

    pub fn text(&self) -> String {
        match self {
            Self::Transport(v) | Self::Auth(v) | Self::Protocol(v) | Self::InvalidResponse(v) => {
                v.clone()
            }
            Self::HttpStatus { status, body } => format!("http status {status}: {body}"),
            Self::Rpc { code, message } => format!("code={code}, message={message}"),
        }
    }

    pub fn contains_case_insensitive(&self, needle: &str) -> bool {
        self.text()
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    }
}

#[derive(Debug, Error)]
pub enum MoneroArbitraError {
    #[error("io error: {0}")]
    Io(std::io::Error),

    #[error("invalid config TOML: {0}")]
    ConfigToml(toml::de::Error),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: EscrowState, to: EscrowState },

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("missing required data: {0}")]
    MissingData(String),

    #[error("threshold not reached: {current}/{threshold}")]
    ThresholdNotReached { current: u16, threshold: u16 },

    #[error("invalid txid")]
    InvalidTxid,

    #[error("insufficient balance: available={available}, needed={needed}")]
    InsufficientBalance { available: u64, needed: u64 },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("wallet-rpc error: {0}")]
    WalletRpc(WalletRpcError),
}

pub type Result<T> = std::result::Result<T, MoneroArbitraError>;
