#![allow(dead_code)]
use super::types::DataRootTuple;
use super::types::*;
use alloy::primitives::B256;
use alloy::primitives::U256;
use alloy::sol_types::SolType;
use core::time::Duration;
use reqwest::Client;
use sha2::Sha256;
use sp1_sdk::{ProverClient, SP1ProvingKey, SP1VerifyingKey};
use std::collections::HashSet;
use std::ops::Add;
use std::{collections::HashMap, env, error::Error};
use subtle_encoding::hex;
use tendermint::block::{Commit, Header};
use tendermint::merkle::simple_hash_from_byte_vectors;
use tendermint::validator::Set as TendermintValidatorSet;
use tendermint::{
    block::signed_header::SignedHeader,
    node::Id,
    validator::{Info, Set},
};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};
use tendermint_light_client_verifier::{options::Options, ProdVerifier, Verdict, Verifier};

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

pub struct TendermintRPCClient {
    url: String,
}

impl Default for TendermintRPCClient {
    fn default() -> Self {
        TendermintRPCClient {
            url: env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL not set"),
        }
    }
}

impl TendermintRPCClient {
    pub fn new(url: String) -> Self {
        TendermintRPCClient { url }
    }

    // Search to find the highest block number to call request_combined_skip on. If the search
    // returns start_block + 1, then we call request_combined_step instead.
    pub async fn find_block_to_request(&mut self, start_block: u64, max_end_block: u64) -> u64 {
        let mut curr_end_block = max_end_block;
        loop {
            if curr_end_block - start_block == 1 {
                return curr_end_block;
            }
            let start_block_validators = self.fetch_validators(start_block).await.unwrap();
            let start_validator_set = Set::new(start_block_validators, None);
            let target_block_validators = self.fetch_validators(curr_end_block).await.unwrap();
            let target_validator_set = Set::new(target_block_validators, None);
            let target_block_commit = self.fetch_commit(curr_end_block).await.unwrap();
            if Self::is_valid_skip(
                start_validator_set,
                target_validator_set,
                target_block_commit.result.signed_header.commit,
            ) {
                return curr_end_block;
            }
            let mid_block = (curr_end_block + start_block) / 2;
            curr_end_block = mid_block;
        }
    }

    /// Fetches all light blocks for the given range of block heights. Inclusive of start and end.
    pub async fn fetch_light_blocks_in_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Vec<LightBlock> {
        let peer_id = self.fetch_peer_id().await.unwrap();
        let batch_size = 25;
        let mut blocks = Vec::new();
        println!(
            "Fetching light blocks in range: {} to {}",
            start_height, end_height
        );

        for batch_start in (start_height..=end_height).step_by(batch_size) {
            let batch_end = std::cmp::min(batch_start + (batch_size as u64) - 1, end_height);
            let mut handles = Vec::new();

            for height in batch_start..=batch_end {
                let fetch_light_block =
                    async move { self.fetch_light_block(height, peer_id).await.unwrap() };
                handles.push(fetch_light_block);
            }

            // Join all the futures in the current batch
            let batch_blocks = futures::future::join_all(handles).await;
            blocks.extend(batch_blocks);
        }

        println!("Finished fetching light blocks!");
        blocks
    }

    /// Retrieves light blocks for the trusted and target block heights.
    pub async fn get_light_blocks(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> (LightBlock, LightBlock) {
        let peer_id = self.fetch_peer_id().await.unwrap();

        let trusted_light_block = self
            .fetch_light_block(trusted_block_height, peer_id)
            .await
            .expect("Failed to generate light block 1");
        let target_light_block = self
            .fetch_light_block(target_block_height, peer_id)
            .await
            .expect("Failed to generate light block 2");
        (trusted_light_block, target_light_block)
    }

    /// Retrieves the latest block height from the Tendermint node.
    pub async fn get_latest_block_height(&self) -> u64 {
        let latest_commit = self.fetch_latest_commit().await.unwrap();
        latest_commit.result.signed_header.header.height.value()
    }

    /// Retrieves the block height from a given block hash.
    pub async fn get_block_height_from_hash(&self, hash: &[u8]) -> u64 {
        let block = self.fetch_block_by_hash(hash).await.unwrap();
        block.result.block.header.height.value()
    }

    /// Sorts the signatures in the signed header based on the descending order of validators' power.
    fn sort_signatures_by_validators_power_desc(
        &self,
        signed_header: &mut SignedHeader,
        validators_set: &ValidatorSet,
    ) {
        let validator_powers: HashMap<_, _> = validators_set
            .validators()
            .iter()
            .map(|v| (v.address, v.power()))
            .collect();

        signed_header.commit.signatures.sort_by(|a, b| {
            let power_a = a
                .validator_address()
                .and_then(|addr| validator_powers.get(&addr))
                .unwrap_or(&0);
            let power_b = b
                .validator_address()
                .and_then(|addr| validator_powers.get(&addr))
                .unwrap_or(&0);
            power_b.cmp(power_a)
        });
    }

    /// Fetches the peer ID from the Tendermint node.
    async fn fetch_peer_id(&self) -> Result<[u8; 20], Box<dyn Error>> {
        let client = Client::new();
        let fetch_peer_id_url = format!("{}/status", self.url);

        let response: PeerIdResponse = client
            .get(fetch_peer_id_url)
            .send()
            .await?
            .json::<PeerIdResponse>()
            .await?;

        Ok(hex::decode(response.result.node_info.id)
            .unwrap()
            .try_into()
            .unwrap())
    }

    /// Fetches a block by its hash.
    async fn fetch_block_by_hash(&self, hash: &[u8]) -> Result<BlockResponse, Box<dyn Error>> {
        let client = Client::new();
        let block_by_hash_url = format!(
            "{}/block_by_hash?hash=0x{}",
            self.url,
            String::from_utf8(hex::encode(hash)).unwrap()
        );
        let response: BlockResponse = client
            .get(block_by_hash_url)
            .send()
            .await?
            .json::<BlockResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a light block by its hash.
    async fn get_light_block_by_hash(&self, hash: &[u8]) -> LightBlock {
        let block = self.fetch_block_by_hash(hash).await.unwrap();
        let peer_id = self.fetch_peer_id().await.unwrap();
        self.fetch_light_block(
            block.result.block.header.height.value(),
            hex::decode(peer_id).unwrap().try_into().unwrap(),
        )
        .await
        .unwrap()
    }

    /// Fetches the latest commit from the Tendermint node.
    async fn fetch_latest_commit(&self) -> Result<CommitResponse, Box<dyn Error>> {
        let url = format!("{}/commit", self.url);
        let client = Client::new();

        let response: CommitResponse = client
            .get(url)
            .send()
            .await?
            .json::<CommitResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches a commit for a specific block height.
    async fn fetch_commit(&self, block_height: u64) -> Result<CommitResponse, Box<dyn Error>> {
        let url = format!("{}/{}", self.url, "commit");

        let client = Client::new();

        let response: CommitResponse = client
            .get(url)
            .query(&[
                ("height", block_height.to_string().as_str()),
                ("per_page", "100"), // helpful only when fetching validators
            ])
            .send()
            .await?
            .json::<CommitResponse>()
            .await?;
        Ok(response)
    }

    /// Fetches validators for a specific block height.
    async fn fetch_validators(&self, block_height: u64) -> Result<Vec<Info>, Box<dyn Error>> {
        let url = format!("{}/{}", self.url, "validators");

        let client = Client::new();
        let mut validators = vec![];
        let mut collected_validators = 0;
        let mut page_index = 1;
        loop {
            let response = client
                .get(&url)
                .query(&[
                    ("height", block_height.to_string().as_str()),
                    ("per_page", "100"),
                    ("page", page_index.to_string().as_str()),
                ])
                .send()
                .await?
                .json::<ValidatorSetResponse>()
                .await?;
            let block_validator_set: BlockValidatorSet = response.result;
            validators.extend(block_validator_set.validators);
            collected_validators += block_validator_set.count.parse::<i32>().unwrap();

            if collected_validators >= block_validator_set.total.parse::<i32>().unwrap() {
                break;
            }
            page_index += 1;
        }

        Ok(validators)
    }

    /// Fetches a light block for a specific block height and peer ID.
    async fn fetch_light_block(
        &self,
        block_height: u64,
        peer_id: [u8; 20],
    ) -> Result<LightBlock, Box<dyn Error>> {
        let commit_response = self.fetch_commit(block_height).await?;
        let mut signed_header = commit_response.result.signed_header;

        let validator_response = self.fetch_validators(block_height).await?;

        let validators = Set::new(validator_response, None);

        let next_validator_response = self.fetch_validators(block_height + 1).await?;
        let next_validators = Set::new(next_validator_response, None);

        self.sort_signatures_by_validators_power_desc(&mut signed_header, &validators);
        Ok(LightBlock::new(
            signed_header,
            validators,
            next_validators,
            Id::new(peer_id),
        ))
    }

    /// Determines if a valid skip is possible between start_block and target_block.
    pub fn is_valid_skip(
        start_validator_set: TendermintValidatorSet,
        target_validator_set: TendermintValidatorSet,
        target_block_commit: Commit,
    ) -> bool {
        let threshold = 1_f64 / 3_f64;
        let mut shared_voting_power = 0_u64;
        let target_block_total_voting_power = target_validator_set.total_voting_power().value();
        let start_block_validators = start_validator_set.validators();
        let mut start_block_idx = 0;
        let start_block_num_validators = start_block_validators.len();

        // Exit if we have already reached the threshold
        while (target_block_total_voting_power as f64) * threshold > shared_voting_power as f64
            && start_block_idx < start_block_num_validators
        {
            if let Some(target_block_validator) =
                target_validator_set.validator(start_block_validators[start_block_idx].address)
            {
                // Confirm that the validator has signed on target_block.
                for sig in target_block_commit.signatures.iter() {
                    if let Some(validator_address) = sig.validator_address() {
                        if validator_address == target_block_validator.address {
                            // Add the shared voting power to the validator
                            shared_voting_power += target_block_validator.power.value();
                        }
                    }
                }
            }
            start_block_idx += 1;
        }

        (target_block_total_voting_power as f64) * threshold <= shared_voting_power as f64
    }

    /// Fetches a header hash for a specific block height.
    pub async fn fetch_header_hash(&self, block_height: u64) -> B256 {
        let peer_id = self.fetch_peer_id().await.unwrap();
        let light_block = self.fetch_light_block(block_height, peer_id).await.unwrap();

        B256::from_slice(light_block.signed_header.header.hash().as_bytes())
    }
}

// The path to the ELF file for the Succinct zkVM program.
pub const TENDERMINT_ELF: &[u8] =
    include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

pub struct TendermintProver {
    pub prover_client: ProverClient,
    pub pkey: SP1ProvingKey,
    pub vkey: SP1VerifyingKey,
}

impl Default for TendermintProver {
    fn default() -> Self {
        Self::new()
    }
}

impl TendermintProver {
    pub fn new() -> Self {
        log::info!("Initializing SP1 ProverClient...");
        let prover_client = ProverClient::new();
        let (pkey, vkey) = prover_client.setup(TENDERMINT_ELF);
        log::info!("SP1 ProverClient initialized");
        Self {
            prover_client,
            pkey,
            vkey,
        }
    }

    // Fetch the inputs for a Blobstream proof.
    pub async fn fetch_input_for_blobstream_proof(
        &self,
        trusted_block_height: u64,
        target_block_height: u64,
    ) -> ProofInputs {
        let tendermint_client = TendermintRPCClient::default();
        let light_blocks = tendermint_client
            .fetch_light_blocks_in_range(trusted_block_height, target_block_height)
            .await;

        let mut headers = Vec::new();
        for light_block in &light_blocks[1..light_blocks.len() - 1] {
            headers.push(light_block.signed_header.header.clone());
        }

        ProofInputs {
            trusted_block_height,
            target_block_height,
            trusted_light_block: light_blocks[0].clone(),
            target_light_block: light_blocks[light_blocks.len() - 1].clone(),
            headers,
        }
    }
}

pub async fn get_data_commitment(start_block: u64, end_block: u64) {
    // If start_block == end_block, then return a dummy commitment.
    // This will occur in the context of data commitment's map reduce when leaves that contain blocks beyond the end_block.

    let route = format!(
        "data_commitment?start={}&end={}",
        start_block.to_string().as_str(),
        end_block.to_string().as_str()
    );

    let url = format!("{}/{}", "https://rpc.lunaroasis.net/", route);

    let res = reqwest::get(url.clone()).await;

    println!("Data Commitment Response: {:?}", res.unwrap())
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
