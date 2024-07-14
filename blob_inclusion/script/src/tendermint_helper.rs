#![allow(dead_code)]
use crate::tendermint_types::*;
use std::{collections::HashMap, env, error::Error};
use tendermint::{
    block::signed_header::SignedHeader,
    node::Id,
    validator::{Info, Set},
};
use tendermint_light_client_verifier::types::{LightBlock, ValidatorSet};
use reqwest::Client;

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
}

