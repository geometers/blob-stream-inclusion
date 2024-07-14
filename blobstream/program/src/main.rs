//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use std::collections::HashSet;
use std::ops::Add;
use std::time::Duration;

use alloy::primitives::U256;
use alloy::sol;

use alloy::primitives::B256;
use alloy::sol_types::SolType;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use tendermint::block::Header;
use tendermint::merkle::simple_hash_from_byte_vectors;
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

/// Construct a bitmap of the intersection of the validators that signed off on the trusted and
/// target header. Use the order of the validators from the trusted header. Equivocates slashing in
/// the case that validators are malicious. 256 is chosen as the maximum number of validators as it
/// is unlikely that Celestia has >256 validators.
pub fn get_validator_bitmap_commitment(
    trusted_light_block: &LightBlock,
    target_light_block: &LightBlock,
) -> U256 {
    // If a validtor has signed off on both headers, add them to the intersection set.
    let mut validator_commit_intersection = HashSet::new();
    for i in 0..trusted_light_block.signed_header.commit.signatures.len() {
        for j in 0..target_light_block.signed_header.commit.signatures.len() {
            let trusted_sig = &trusted_light_block.signed_header.commit.signatures[i];
            let target_sig = &target_light_block.signed_header.commit.signatures[j];

            if trusted_sig.is_commit()
                && target_sig.is_commit()
                && trusted_sig.validator_address() == target_sig.validator_address()
            {
                validator_commit_intersection.insert(trusted_sig.validator_address().unwrap());
            }
        }
    }

    // Construct the validator bitmap.
    let mut validator_bitmap = [false; 256];
    for (i, validator) in trusted_light_block
        .validators
        .validators()
        .iter()
        .enumerate()
    {
        if validator_commit_intersection.contains(&validator.address) {
            validator_bitmap[i] = true;
        }
    }

    // Convert the validator bitmap to a U256.
    convert_bitmap_to_u256(validator_bitmap)
}

// Convert a boolean array to a U256. Used to commit to the validator bitmap.
pub fn convert_bitmap_to_u256(arr: [bool; 256]) -> U256 {
    let mut res = U256::from(0);
    for (index, &value) in arr.iter().enumerate() {
        if value {
            res = res.add(U256::from(1) << index)
        }
    }
    res
}

pub fn main() {
    // Read in the proof inputs. Note: Use a slice, as bincode is unable to deserialize protobuf.
    let proof_inputs_vec = sp1_zkvm::io::read_vec();
    let proof_inputs = serde_cbor::from_slice(&proof_inputs_vec).unwrap();

    let ProofInputs {
        trusted_block_height,
        target_block_height,
        trusted_light_block,
        target_light_block,
        headers,
    } = proof_inputs;

    let verdict = get_header_update_verdict(&trusted_light_block, &target_light_block);

    // If the Verdict is not Success, panic.
    match verdict {
        Verdict::Success => (),
        Verdict::NotEnoughTrust(voting_power_tally) => {
            panic!(
                "Not enough trust in the trusted header, voting power tally: {:?}",
                voting_power_tally
            );
        }
        Verdict::Invalid(err) => panic!(
            "Could not verify updating to target_block, error: {:?}",
            err
        ),
    }

    // Compute the data commitment across the range.
    let mut all_headers = Vec::new();
    all_headers.push(trusted_light_block.signed_header.header.clone());
    all_headers.extend(headers);
    all_headers.push(target_light_block.signed_header.header.clone());
    let data_commitment = B256::from_slice(&compute_data_commitment(&all_headers));
    println!("data_commitment: {:?}", data_commitment);

    // Get the commitment to the validator bitmap.
    let validator_bitmap_u256 =
        get_validator_bitmap_commitment(&trusted_light_block, &target_light_block);

    // ABI encode the proof outputs to bytes and commit them to the zkVM.
    let trusted_header_hash =
        B256::from_slice(trusted_light_block.signed_header.header.hash().as_bytes());
    let target_header_hash =
        B256::from_slice(target_light_block.signed_header.header.hash().as_bytes());
    let proof_outputs = ProofOutputs::abi_encode(&(
        trusted_header_hash,
        target_header_hash,
        data_commitment,
        trusted_block_height,
        target_block_height,
        validator_bitmap_u256,
    ));
    sp1_zkvm::io::commit_slice(&proof_outputs);
}
