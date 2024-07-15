use std::fs;

use blob_inclusion_script::request::{BlobRequest, RawBlobRequest};
use blob_inclusion_script::tendermint_helper::TendermintRPCClient;
use celestia_types::hash::Hash;
use celestia_types::nmt::NamespacedHashExt;

use blob_inclusion_script::{get_blob, get_blob_proof, get_header_by_height};
use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};

use nmt_rs::simple_merkle::db::MemDb;
use nmt_rs::simple_merkle::tree::MerkleTree;
use nmt_rs::TmSha2Hasher;

use tokio::runtime;

pub const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct ScriptArgs {
    /// Start blobstream block.
    #[clap(long)]
    pub start_height: u64,
    /// End blobstream block.
    #[clap(long, env)]
    pub end_height: u64,
    /// Number of blob requests
    #[clap(long, env)]
    pub num_requests: u8,
    /// Blobs request json
    #[clap(long, env)]
    pub request_path: String,
}

/// Generate an inclusion proof of a blob at `block_height`
/// Example:
/// ```
/// RUST_LOG=info cargo run --release -- --start-height=1 --end-height=2 --num-requests=2 --request-path="requests.json"
/// ```
fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let prover = ProverClient::new();
    let (pkey, vkey) = prover.setup(ELF);

    let mut stdin = SP1Stdin::new();
    let rt = runtime::Runtime::new()?;

    let ScriptArgs {
        start_height,
        end_height,
        num_requests,
        request_path,
    } = ScriptArgs::parse();

    let tendermint_client = TendermintRPCClient::default();
    let light_blocks = rt.block_on(async {
        tendermint_client
            .fetch_light_blocks_in_range(start_height, end_height)
            .await
    });

    let string = fs::read_to_string(&request_path).unwrap();
    let blob_requests: Vec<RawBlobRequest> = serde_json::from_str(&string).unwrap();
    let blob_requests: Vec<BlobRequest> = blob_requests
        .into_iter()
        .map(|b| b.try_into().unwrap())
        .collect();
    assert_eq!(blob_requests.len(), num_requests as usize);
    stdin.write(&num_requests);

    for blob_request in blob_requests {
        let BlobRequest {
            block_height,
            commitment,
            namespace,
        } = blob_request;

        let dah = rt.block_on(async { get_header_by_height(block_height).await });

        let blob = rt.block_on(async { get_blob(block_height, commitment, namespace).await });
        let shares = blob.to_shares().unwrap();

        // NMT range proofs, from leaves into row roots.
        let proofs =
            rt.block_on(async { get_blob_proof(block_height, commitment, namespace).await });

        let eds_row_roots = &dah.dah.row_roots();
        let eds_column_roots = &dah.dah.column_roots();
        let data_tree_leaves: Vec<_> = eds_row_roots
            .iter()
            .chain(eds_column_roots.iter())
            .map(|root| root.to_array())
            .collect();

        // "Data root" is the merkle root of the EDS row and column roots
        let hasher: TmSha2Hasher = TmSha2Hasher {}; // Tendermint Sha2 hasher
        let mut tree: MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher> = MerkleTree::with_hasher(hasher);
        data_tree_leaves
            .iter()
            .for_each(|leaf| tree.push_raw_leaf(leaf));
        // Ensure that the data root is the merkle root of the EDS row and column roots
        assert_eq!(dah.dah.hash(), Hash::Sha256(tree.root()));

        // extended data square (EDS) width
        let eds_width = eds_row_roots.len();
        let ods_width = eds_width / 2;

        let div_up = |a: usize, b: usize| -> usize { (a + (b - 1)) / b };

        let blob_index: usize = blob.index.unwrap() as usize;
        let num_shares: usize = shares.len();
        let first_row_index: usize = blob_index / eds_width;
        let mut last_row_index = first_row_index;
        {
            let first_row_shares = ods_width - (blob_index % eds_width);
            if num_shares > first_row_shares {
                let remaining_shares: usize = num_shares - first_row_shares;
                last_row_index += div_up(remaining_shares, ods_width);
            }
        }
        let num_rows: usize = last_row_index - first_row_index + 1;

        // For each row spanned by the blob, you should have one NMT range proof into a row root.
        assert_eq!(proofs.len(), num_rows);

        let mut start: usize = 0;
        proofs
            .iter()
            .zip(eds_row_roots[first_row_index..=last_row_index].iter())
            .for_each(|(proof, root)| {
                let end = start + (proof.end_idx() - proof.start_idx()) as usize;
                let verify = proof.verify_range(root, &shares[start..end], namespace.into());
                assert!(verify.is_ok());
                start = end;
            });

        let range_proof: nmt_rs::simple_merkle::proof::Proof<TmSha2Hasher> =
            tree.build_range_proof(first_row_index..first_row_index + num_rows);

        // Write the Data Availability Header data root
        stdin.write(&dah.dah.hash());
        // write the block height
        stdin.write(&block_height);
        // write "num rows" spanned by the blob
        stdin.write(&num_rows);
        // write namespace
        stdin.write(&namespace);
        // write the range proof
        stdin.write(&range_proof);
        // write the row roots
        for row_root in eds_row_roots[first_row_index..=last_row_index].iter() {
            stdin.write(&row_root);
        }
        // write the blob
        stdin.write(&blob);
        // write the blob proofs {
        for proof in proofs {
            stdin.write(&proof);
        }
    }

    let headers: Vec<_> = light_blocks
        .iter()
        .map(|b| b.signed_header.header.clone())
        .collect();
    // Write blobstream headers
    let encoded_headers = serde_cbor::to_vec(&headers).unwrap();
    stdin.write_vec(encoded_headers);

    // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
    let proof = prover.prove(&pkey, stdin).expect("proving failed");
    println!("Successfully generated proof!");

    // Verify proof.
    prover.verify(&proof, &vkey).expect("Verification failed");

    Ok(())
}
