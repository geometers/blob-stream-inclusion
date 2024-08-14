//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use celestia_types::hash::Hash;
use celestia_types::Blob;
use nmt_rs::simple_merkle::proof::Proof;
use nmt_rs::simple_merkle::tree::MerkleHash;
use nmt_rs::NamespacedHash;
use nmt_rs::TmSha2Hasher;

use celestia_types::nmt::Namespace;
use celestia_types::nmt::{NamespaceProof, NamespacedHashExt};
use tendermint::block::Header;
use tendermint::merkle::simple_hash_from_byte_vectors;

use alloy::primitives::B256;
use alloy::sol;
use alloy::sol_types::SolType;
use sha2::Sha256;

pub type DataRootTuple = sol! {
    tuple(uint64, bytes32)
};

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

pub fn main() {
    // Read the number of blob requests
    let num_blobs: u8 = sp1_zkvm::io::read();

    let mut data_roots = vec![];
    for _ in 0..num_blobs {
        // Read the Data Availability Header data root
        let data_root: Hash = sp1_zkvm::io::read();
        data_roots.push(data_root);
        // Read the block height
        let _block_height: u64 = sp1_zkvm::io::read();
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

        // For each row spanned by the blob, we have a NMT range proof
        let mut proofs = vec![];
        for _ in 0..num_rows {
            let proof = sp1_zkvm::io::read::<NamespaceProof>();
            proofs.push(proof);
        }

        // We have one NMT range proof for each row spanned by the blob
        // Verify that the blob's shares go into the respective row roots
        {
            let mut start = 0;
            for i in 0..(num_rows as usize) {
                let proof = &proofs[i];
                let root: &NamespacedHash<29> = &row_roots[i];
                let end: usize = start + (proof.end_idx() as usize - proof.start_idx() as usize);
                assert!(proof
                    .verify_range(root, &shares[start..end], namespace.into())
                    .is_ok());
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
                .verify_range(&data_root.as_bytes().try_into().unwrap(), &blob_row_root_hashes)
                .is_ok());
        }

        sp1_zkvm::io::commit(&blob.namespace.as_bytes());
        sp1_zkvm::io::commit(&blob.data);
    }

    // Read blobstream headers
    let headers = sp1_zkvm::io::read_vec();
    let headers: Vec<Header> = serde_cbor::from_slice(&headers).unwrap();
    // Verify that each data root is included in the blobstream headers
    let blobstream_data_hashes: Vec<_> =
        headers.iter().map(|h| h.data_hash.unwrap()).collect();
    for data_root in data_roots.iter() {
        let data_root: [u8; 32] = data_root.as_bytes().try_into().unwrap();
        assert!(blobstream_data_hashes.contains(&data_root.to_vec().try_into().unwrap()));
    }

    let blobstream_commitment = compute_data_commitment(&headers);
    println!(
        "blobstream_commitment: {:?}",
        B256::from_slice(&blobstream_commitment)
    );
    sp1_zkvm::io::commit(&blobstream_commitment);
}
