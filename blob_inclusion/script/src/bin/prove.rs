use std::fs;
use std::fs::File;
use std::io::Write;

use blob_inclusion_script::tendermint_helper::TendermintRPCClient;
use celestia_types::hash::Hash;
use celestia_types::nmt::Namespace;
use celestia_types::nmt::NamespacedHashExt;
use celestia_types::Commitment;
use clap::Parser;
use sp1_sdk::{SP1Stdin, ProverClient};
use blob_inclusion_script::{get_blob, get_blob_proof, get_header_by_height};

use nmt_rs::simple_merkle::db::MemDb;
use nmt_rs::simple_merkle::tree::MerkleTree;
use nmt_rs::TmSha2Hasher;

use tokio::runtime;

pub const ELF: &[u8] =
    include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct ScriptArgs {
    /// Start blobstream block.
    #[clap(long)]
    pub start_height: u64,
    /// End blobstream block.
    #[clap(long, env)]
    pub end_height: u64,
    /// Block height which blob is in
    #[clap(long, env)]
    pub block_height: u64,
    /// Blob namespace
    #[clap(long, env)]
    pub namespace: String,
    /// Blob commitment
    #[clap(long, env)]
    pub commitment: String,
}

/// Generate an inclusion proof of a blob at `block_height`
/// Example:
/// ```
/// RUST_LOG=info cargo run --bin script --release -- --start-height=1 --end-height=2 --block-height=3 --namespace="namespace" --commitment="commitment"
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
        block_height,
        namespace,
        commitment,
    } = ScriptArgs::parse();

    let tendermint_client = TendermintRPCClient::default();
    let light_blocks = rt.block_on( async {
        tendermint_client.fetch_light_blocks_in_range(start_height, end_height).await
    });
    let headers: Vec<_> = light_blocks.iter().map(|b| b.signed_header.header.clone()).collect();

    let namespace = Namespace::new_v0(&hex::decode(namespace).unwrap())?;
    let commitment = Commitment(hex::decode(commitment).unwrap().try_into().unwrap());


    let dah = match fs::read_to_string("dah.json") {
        Ok(string) => serde_json::from_str(&string).unwrap(),
        _ => {
            let dah = rt.block_on(async { get_header_by_height(block_height).await });
            let json_string = serde_json::to_string(&dah)?;
            let mut file = File::create("dah.json")?;
            file.write_all(json_string.as_bytes())?;
            dah
        }
    };
    let blob = match fs::read_to_string("blob.json") {
        Ok(string) => serde_json::from_str(&string).unwrap(),
        _ => {
            let blob = rt.block_on(async { get_blob(block_height, commitment, namespace).await });
            let json_string = serde_json::to_string(&blob)?;
            let mut file = File::create("blob.json")?;
            file.write_all(json_string.as_bytes())?;
            blob
        }
    };

    // NMT range proofs, from leaves into row roots.
    let proofs = match fs::read_to_string("proofs.json") {
        Ok(string) => serde_json::from_str(&string).unwrap(),
        _ => {
            let proofs =
                rt.block_on(async { get_blob_proof(block_height, commitment, namespace).await });
            let json_string = serde_json::to_string(&proofs)?;
            let mut file = File::create("proofs.json")?;
            file.write_all(json_string.as_bytes())?;
            proofs
        }
    };

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
    for leaf in data_tree_leaves {
        tree.push_raw_leaf(&leaf);
    }
    // Ensure that the data root is the merkle root of the EDS row and column roots
    assert_eq!(dah.dah.hash(), Hash::Sha256(tree.root()));

    // extended data square (EDS) size
    let eds_size = eds_row_roots.len();
    let ods_size = eds_size / 2;

    let blob_index: usize = blob.index.unwrap().try_into().unwrap();
    let num_shares: usize = std::cmp::max(1, blob.data.len() / 512);
    let num_rows = std::cmp::max(1, num_shares / ods_size);
    let first_row_index: usize = blob_index / eds_size;
    let last_row_index: usize = first_row_index + num_rows;

    let shares = blob.to_shares().unwrap();

    let mut start: usize = 0;
    proofs
        .iter()
        .zip(eds_row_roots[first_row_index..last_row_index].iter())
        .for_each(|(proof, root)| {
            let end = start + (proof.end_idx() - proof.start_idx()) as usize;
            let verify = proof.verify_range(root, &shares[start..end], namespace.into());
            assert!(verify.is_ok());
            start = end;
        });

    // For each row spanned by the blob, you should have one NMT range proof into a row root.
    assert_eq!(proofs.len(), num_rows);

    let range_proof: nmt_rs::simple_merkle::proof::Proof<TmSha2Hasher> =
        tree.build_range_proof(first_row_index..last_row_index);

    // Write the Data Availability Header data root
    stdin.write_vec(dah.dah.hash().as_bytes().to_vec());
    // write the block height
    stdin.write(&block_height);
    // write "num rows" spanned by the blob
    stdin.write(&num_rows);
    // write namespace
    stdin.write(&namespace);
    // write the range proof
    stdin.write(&range_proof);
    // write the row roots
    for row_root in eds_row_roots[first_row_index..last_row_index].iter() {
        stdin.write(&row_root);
    }
    // write the blob
    stdin.write(&blob);
    // write the blob proofs {
    for proof in proofs {
        stdin.write(&proof);
    }
    // Write blobstream headers
    let encoded_headers = serde_cbor::to_vec(&headers).unwrap();
    stdin.write_vec(encoded_headers);

    // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
    let proof = prover
        .prove(&pkey, stdin)
        .expect("proving failed");
    println!("Successfully generated proof!");

    // Verify proof.
    prover
        .verify(&proof, &vkey)
        .expect("Verification failed");

    Ok(())
}
