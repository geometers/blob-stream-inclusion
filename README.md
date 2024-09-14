# SP1 Blobstream + Blob inclusion proof

## Setup
- [Install SP1.](https://docs.succinct.xyz/getting-started/install.html)
- Create a `.env` file and copy the `.env.example` file there. Fill in your own `SP1_PRIVATE_KEY` and
`LIGHT_NODE_AUTH_TOKEN` (see below for instructions on obtaining them).

### Celestia
- To retrieve blobs and extended headers, you will need access to a Celestia light node. See here
  for instructions on setting one up:
  [docs.celestia.org/nodes/light-node](https://docs.celestia.org/nodes/light-node)
- If you're running a light node, get the authentication token using the following command and add it to the `.env` file:
  `export LIGHT_NODE_AUTH_TOKEN=$(celestia light auth admin --p2p.network celestia)`
  (See this tutorial if you need further instructions:
  [docs.celestia.org/developers/node-tutorial#auth-token](https://docs.celestia.org/developers/node-tutorial#auth-token))
- Run the Celestia light node:
```bash
celestia light start --core.ip rpc.celestia.pops.one --p2p.network celestia
```

### SP1
- If you're making proofs on your local machine, set `SP1_PROVER=local` in your `.env`
- To access the SP1 prover network, you will need the `SP1_PRIVATE_KEY` of a whitelisted address.
See here for how to obtain one:
[docs.succinct.xyz/prover-network/setup.html](https://docs.succinct.xyz/generating-proofs/prover-network/key-setup.html)

## e2e test
Check that both these programs print the same data commitment (the data root tuple root).

### Blobstream
This generates a proof at `blobstream/script/proof-with-pis.json`.

```bash
cd blobstream/script && cargo run --release \
-- --trusted-block=1865870 \
--target-block=1865890
```

### Blob inclusion
This generates a proof at `blob_inclusion/script/proof-with-pis.json`.

```bash
cd blob_inclusion/script && cargo run --release \
-- --start-height=1865870 \
--end-height=1865890 \
--num-requests=1 \
--request-path=requests.json
```

## Arbitrary blobs
To run this for arbitrary blobs, edit the `blob_inclusion/script/requests.json` file and adjust the
blobstream heights accordingly.
