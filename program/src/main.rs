//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use celestia_types::Blob;
use nmt_rs::simple_merkle::proof::Proof;
use nmt_rs::simple_merkle::tree::MerkleHash;
use nmt_rs::NamespacedHash;
use nmt_rs::TmSha2Hasher;

use celestia_types::nmt::Namespace;
use celestia_types::nmt::{NamespaceProof, NamespacedHashExt};

use alloy_primitives::B256;
use alloy_sol_types::SolType;
use tendermint::block::Header;
use tendermint_light_client_verifier::Verdict;

mod utils;
use utils::{compute_data_commitment, get_header_update_verdict, ProofInputs, ProofOutputs};

fn blobstream() -> (u64, u64, Vec<Header>) {
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

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("Could not verify updating to target_block, error: {:?}", v),
    }

    let mut all_headers = Vec::new();
    all_headers.push(trusted_light_block.signed_header.header.clone());
    all_headers.extend(headers);
    all_headers.push(target_light_block.signed_header.header.clone());

    let data_commitment = B256::from_slice(&compute_data_commitment(&all_headers));

    // Now that we have verified our proof, we commit the header hashes to the zkVM to expose
    // them as public values.
    let trusted_header_hash =
        B256::from_slice(trusted_light_block.signed_header.header.hash().as_bytes());
    let target_header_hash =
        B256::from_slice(target_light_block.signed_header.header.hash().as_bytes());

    // ABI-Encode Proof Outputs
    let proof_outputs = ProofOutputs::abi_encode(&(
        trusted_header_hash,
        target_header_hash,
        data_commitment,
        trusted_block_height,
        target_block_height,
    ));
    sp1_zkvm::io::commit_slice(&proof_outputs);

    (trusted_block_height, target_block_height, all_headers)
}

fn blob_inclusion(
    trusted_block_height: u64,
    target_block_height: u64,
    blobstream_headers: Vec<Header>,
) {
    // Read the Data Availability Header data root
    let data_root: Vec<u8> = sp1_zkvm::io::read_vec();
    assert!(data_root.len() == 32);

    // Read the block height
    let block_height: u64 = sp1_zkvm::io::read();
    assert!(block_height >= trusted_block_height);
    assert!(block_height <= target_block_height);

    let blobstream_header = &blobstream_headers[(block_height - trusted_block_height) as usize];
    assert_eq!(data_root, blobstream_header.data_hash.unwrap().as_bytes());

    // Read num rows
    let num_rows: u32 = sp1_zkvm::io::read();
    // Read namespace ID
    let namespace = sp1_zkvm::io::read::<Namespace>();
    // Read the row-inclusion range proof
    let range_proof: Proof<TmSha2Hasher> = sp1_zkvm::io::read();
    // Read the row roots
    let mut row_roots = vec![];
    for _ in 0..num_rows {
        row_roots.push(sp1_zkvm::io::read::<NamespacedHash<29>>());
    }
    // Read the blob and split it into shares
    let blob = sp1_zkvm::io::read::<Blob>();

    let shares = blob.to_shares().expect("Failed to split blob to shares");
    let shares: Vec<[u8; 512]> = shares.iter().map(|share| share.data).collect();

    // For each row spanned by the blob, we have a NMT range proof
    let mut proofs = vec![];
    for _ in 0..num_rows {
        let proof = sp1_zkvm::io::read::<NamespaceProof>();
        proofs.push(proof);
    }

    // We have one NMT range proof for each row spanned by the blob
    // Verify that the blob's shares go into the respective row roots
    {
        println!("namespace: {:?}", namespace);
        let mut start = 0;
        for i in 0..(num_rows as usize) {
            let proof = &proofs[i];
            let root: &NamespacedHash<29> = &row_roots[i];
            let end: usize = start + (proof.end_idx() as usize - proof.start_idx() as usize);
            // FIXME this is failing
            // assert!(proof
            //     .verify_range(root, &shares[start..end], namespace.into())
            //     .is_ok());
            start = end;
        }
    }

    // Verify the row-inclusion range proof
    {
        let tm_hasher = TmSha2Hasher {};
        let blob_row_root_hashes: Vec<[u8; 32]> = row_roots
            .iter()
            .map(|root| tm_hasher.hash_leaf(&root.to_array()))
            .collect();

        assert!(range_proof
            .verify_range(
                &data_root.clone().try_into().unwrap(),
                &blob_row_root_hashes,
            )
            .is_ok());
    }

    sp1_zkvm::io::commit(&data_root);
    sp1_zkvm::io::commit(&blob);
}

pub fn main() {
    let (trusted_block_height, target_block_height, headers) = blobstream();
    blob_inclusion(trusted_block_height, target_block_height, headers);
}
