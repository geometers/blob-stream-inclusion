use celestia_rpc::{BlobClient, Client, HeaderClient};
use celestia_types::{
    nmt::{Namespace, NamespaceProof},
    Blob, Commitment, ExtendedHeader,
};

pub mod request;
pub mod tendermint_helper;
pub mod tendermint_types;

const URL: &str = "http://localhost:26658";
const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJwdWJsaWMiLCJyZWFkIiwid3JpdGUiLCJhZG1pbiJdfQ.v-iP2JSifg-mQyyi2BRnQG5tIybTyy-df7_g9R3Ms2g";

pub async fn get_header_by_height(height: u64) -> ExtendedHeader {
    let client = Client::new(URL, Some(TOKEN))
        .await
        .expect("Failed creating rpc client");

    // first get the header of the block you want to fetch the EDS from
    client
        .header_get_by_height(height)
        .await
        .expect("Failed fetching header")
}

pub async fn get_blob(height: u64, commitment: Commitment, namespace: Namespace) -> Blob {
    let client = Client::new(URL, Some(TOKEN))
        .await
        .expect("Failed creating rpc client");
    client
        .blob_get(height, namespace, commitment)
        .await
        .expect("Failed fetching blob")
}

pub async fn get_blob_proof(
    height: u64,
    commitment: Commitment,
    namespace: Namespace,
) -> Vec<NamespaceProof> {
    let client = Client::new(URL, Some(TOKEN))
        .await
        .expect("Failed creating rpc client");
    client
        .blob_get_proof(height, namespace, commitment)
        .await
        .expect("Failed fetching blob proof")
}
