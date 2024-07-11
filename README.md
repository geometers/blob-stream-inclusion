# SP1 Blobstream + Blob inclusion proof

## Hard-coded example blob
```bash
cd script && cargo run --release \
-- --trusted-block=1266372 --target-block=1266374 --block-height=1266373 \
--namespace="072c4a8666dfa3ae" \
--commitment="2b8b01bb6f77b840af59063fec2c644eb40fcc9992aab7d04f84e563cdf02449"
```

## Arbitrary blobs
To run this for arbitrary blobs, you will need access to a [Celestia light node](https://docs.celestia.org/nodes/light-node):

```bash
celestia light start --core.ip rpc.celestia.pops.one --p2p.network celestia
```
