use alloy_sol_types::{sol, SolType};
use core::time::Duration;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tendermint::{block::Header, merkle::simple_hash_from_byte_vectors};
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

pub type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

/// bytes32 trusted_header_hash;
/// bytes32 target_header_hash;
/// bytes32 data_commitment;
/// uint64 trusted_block;
/// uint64 target_block;
pub type ProofOutputs = sol! {
    tuple(bytes32, bytes32, bytes32, uint64, uint64)
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

/// Get the verdict for the header update from trusted_block to target_block.
pub fn get_header_update_verdict(trusted_block: &LightBlock, target_block: &LightBlock) -> Verdict {
    let opt = Options {
        // TODO: Should we set a custom threshold?
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };

    let vp = ProdVerifier::default();
    // TODO: What should we set the verify time to? This prevents outdated headers from being used.
    let verify_time = target_block.time() + Duration::from_secs(20);
    vp.verify_update_header(
        target_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}

/// Compute the data commitment for the given headers.
pub fn compute_data_commitment(headers: &[Header]) -> [u8; 32] {
    let mut encoded_data_root_tuples: Vec<Vec<u8>> = Vec::new();
    for i in 1..headers.len() {
        let prev_header = &headers[i - 1];
        let curr_header = &headers[i];
        // Checks that chain of headers is well-formed.
        if prev_header.hash() != curr_header.last_block_id.unwrap().hash {
            panic!("invalid header");
        }

        let data_hash: [u8; 32] = prev_header
            .data_hash
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();

        let data_root_tuple = DataRootTuple::abi_encode(&(prev_header.height.value(), data_hash));
        encoded_data_root_tuples.push(data_root_tuple);
    }

    simple_hash_from_byte_vectors::<Sha256>(&encoded_data_root_tuples)
}
