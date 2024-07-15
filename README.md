# SP1 Blobstream + Blob inclusion proof

## e2e
Check that both these programs print the same data commitment (the data root tuple root):
`0x5ffcedf38491ac2a6e427370f34438011b92cf9f1e50ce42ca58e43ee9722369`

### Blobstream
```bash
cd blobstream/script && cargo run --release \
-- --trusted-block=1279714 \
--target-block=1279716
```

### Blob inclusion
```bash
cd blob_inclusion/script && cargo run --release \
-- --start-height=1279714 \
--end-height=1279716 \
--block-height=1279715 \
--namespace=7463656c6573746961 \
--commitment=b596140c4ae3c16f14d02878bc0ac3f3702bdee8a2d31218223130673f0ac220
```

## Arbitrary blobs
To run this for arbitrary blobs, you will need access to a [Celestia light node](https://docs.celestia.org/nodes/light-node):

```bash
celestia light start --core.ip rpc.celestia.pops.one --p2p.network celestia
```
