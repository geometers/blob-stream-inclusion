# SP1 Blobstream + Blob inclusion proof

## e2e
Check that both these programs print the same data commitment (the data root tuple root):
`0x0a4e67626957c8691c95fce5c0c391fb731c27ef0eed6973b150152c9fbb3058`

### Blobstream
```bash
cd blobstream/script && cargo run --release \
-- --trusted-block=1279715 \
--target-block=1279735
```

### Blob inclusion
```bash
cd blob_inclusion/script && cargo run --release \
-- --start-height=1279715 \
--end-height=1279735 \
--num-requests=2 \
--request-path=requests.json
```

## Arbitrary blobs
To run this for arbitrary blobs, you will need access to a [Celestia light node](https://docs.celestia.org/nodes/light-node):

```bash
celestia light start --core.ip rpc.celestia.pops.one --p2p.network celestia
```
