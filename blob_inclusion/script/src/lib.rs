use celestia_rpc::{BlobClient, Client, HeaderClient};
use celestia_types::{
    nmt::{Namespace, NamespaceProof},
    Blob, Commitment, ExtendedHeader,
};

pub mod request;
pub mod tendermint_helper;
pub mod tendermint_types;

pub struct CelestiaLightNodeClient {
    url: String,
    token: Option<String>,
}

impl CelestiaLightNodeClient {
    pub fn new(url: String, token: Option<String>) -> Self {
        CelestiaLightNodeClient { url, token }
    }

    pub async fn get_header_by_height(&self, height: u64) -> ExtendedHeader {
        let client = Client::new(&self.url, self.token.as_deref())
            .await
            .expect("Failed creating rpc client");

        // first get the header of the block you want to fetch the EDS from
        client
            .header_get_by_height(height)
            .await
            .expect("Failed fetching header")
    }

    pub async fn get_blob(
        &self,
        height: u64,
        commitment: Commitment,
        namespace: Namespace,
    ) -> Blob {
        let client = Client::new(&self.url, self.token.as_deref())
            .await
            .expect("Failed creating rpc client");
        client
            .blob_get(height, namespace, commitment)
            .await
            .expect("Failed fetching blob")
    }

    pub async fn get_blob_proof(
        &self,
        height: u64,
        commitment: Commitment,
        namespace: Namespace,
    ) -> Vec<NamespaceProof> {
        let client = Client::new(&self.url, self.token.as_deref())
            .await
            .expect("Failed creating rpc client");
        client
            .blob_get_proof(height, namespace, commitment)
            .await
            .expect("Failed fetching blob proof")
    }
}
