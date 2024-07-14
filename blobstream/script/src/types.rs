#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use tendermint::{
    block::{self, signed_header::SignedHeader, Header},
    validator::Info,
    Block,
};
use tendermint_light_client_verifier::types::LightBlock;

use alloy::sol;

pub type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

/// bytes32 trusted_header_hash;
/// bytes32 target_header_hash;
/// bytes32 data_commitment;
/// uint64 trusted_block;
/// uint64 target_block;
/// uint256 validator_bitmap;
pub type ProofOutputs = sol! {
    tuple(bytes32, bytes32, bytes32, uint64, uint64, uint256)
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofInputs {
    pub trusted_block_height: u64,
    pub target_block_height: u64,
    pub trusted_light_block: LightBlock,
    pub target_light_block: LightBlock,
    /// Exclusive of trusted_light_block and target_light_block's headers
    pub headers: Vec<Header>,
}

#[derive(Debug, Deserialize)]
pub struct PeerIdResponse {
    pub result: PeerIdWrapper,
}

#[derive(Debug, Deserialize)]
pub struct PeerIdWrapper {
    pub node_info: NodeInfoWrapper,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfoWrapper {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockResponse {
    pub result: BlockWrapper,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct BlockWrapper {
    pub block_id: Option<block::Id>,
    pub block: Block,
}

#[derive(Debug, Deserialize)]
pub struct CommitResponse {
    pub result: SignedHeaderWrapper,
}

#[derive(Debug, Deserialize)]
pub struct SignedHeaderWrapper {
    pub signed_header: SignedHeader,
}

#[derive(Debug, Deserialize)]
pub struct ValidatorSetResponse {
    pub result: BlockValidatorSet,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct BlockValidatorSet {
    pub block_height: String,
    pub validators: Vec<Info>,
    pub count: String,
    pub total: String,
}
