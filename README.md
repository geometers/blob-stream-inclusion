# SP1 Blobstream + Blob inclusion proof

## Hard-coded example blob
```bash
cd script && cargo run --release \
-- --trusted-block=1279714 --target-block=1279716 --block-height=1279715 \
--namespace=7463656c6573746961 \
--commitment=b596140c4ae3c16f14d02878bc0ac3f3702bdee8a2d31218223130673f0ac220
```

## Arbitrary blobs
To run this for arbitrary blobs, you will need access to a [Celestia light node](https://docs.celestia.org/nodes/light-node):

```bash
celestia light start --core.ip rpc.celestia.pops.one --p2p.network celestia
```
