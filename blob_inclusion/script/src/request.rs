use celestia_types::{nmt::Namespace, Commitment};
use hex::FromHexError;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BlobRequest {
    pub block_height: u64,
    pub commitment: Commitment,
    pub namespace: Namespace,
}

#[derive(Deserialize, Debug)]
pub struct RawBlobRequest {
    block_height: u64,
    commitment: String,
    namespace: String,
}

impl TryFrom<RawBlobRequest> for BlobRequest {
    type Error = FromHexError;

    fn try_from(value: RawBlobRequest) -> std::result::Result<Self, Self::Error> {
        let commitment: Commitment = Commitment(hex::decode(value.commitment)?.try_into().unwrap());
        let namespace: Namespace = Namespace::new_v0(&hex::decode(value.namespace)?).unwrap();

        Ok(Self {
            block_height: value.block_height,
            commitment,
            namespace,
        })
    }
}

impl TryFrom<&str> for BlobRequest {
    type Error = FromHexError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let raw_blob: RawBlobRequest = serde_json::from_str(value).unwrap();
        raw_blob.try_into()
    }
}
