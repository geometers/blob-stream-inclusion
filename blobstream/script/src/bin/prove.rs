use blobstream_script::helper::*;
use clap::Parser;
use sp1_sdk::SP1Stdin;
use tokio::runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct ScriptArgs {
    /// Trusted block.
    #[clap(long)]
    pub trusted_block: u64,
    /// Target block.
    #[clap(long, env)]
    pub target_block: u64,
}

/// Generate a Blobstream proof between the given trusted and target blocks.
/// Generate an inclusion proof of a blob at `block_height`
/// Example:
/// ```
/// RUST_LOG=info cargo run --bin script --release -- --trusted-block=1 --target-block=5
/// ```
fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let prover = TendermintProver::new();
    let mut stdin = SP1Stdin::new();

    let ScriptArgs {
        trusted_block,
        target_block,
    } = ScriptArgs::parse();

    sp1_sdk::utils::setup_logger();

    let rt = runtime::Runtime::new()?;

    // Fetch the inputs for the proof.
    let inputs = rt.block_on(async {
        prover
            .fetch_input_for_blobstream_proof(trusted_block, target_block)
            .await
    });
    let encoded_proof_inputs = serde_cbor::to_vec(&inputs).unwrap();
    stdin.write_vec(encoded_proof_inputs);

    let now = std::time::Instant::now();
    // Generate the proof. Depending on SP1_PROVER env, this may be a local or network proof.
    let proof = prover
        .prover_client
        .prove_plonk(&prover.pkey, stdin)
        .expect("proving failed");
    println!("Successfully generated proof!");
    let elapsed_time = now.elapsed();
    println!(
        "Running blobstream prove_plonk() took {} seconds.",
        elapsed_time.as_secs()
    );

    // Verify proof.
    prover
        .prover_client
        .verify_plonk(&proof, &prover.vkey)
        .expect("Verification failed");

    // Save the proof as binary.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");

    // Save the proof as JSON.
    std::fs::write("proof-with-pis.json", serde_json::to_string(&proof).unwrap()).unwrap();

    Ok(())
}
