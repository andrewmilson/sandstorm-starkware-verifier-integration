use std::{fmt::Display, fs::File, path::Path};

use ark_serialize::CanonicalDeserialize;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ministark::Proof;
use num_bigint::BigUint;
use ruint::{aliases::U256, uint};
use sandstorm_claims::sharp::utils::to_montgomery;
use sandstorm_binary::{CompiledProgram, AirPublicInput};
use sandstorm_claims::sharp;
use sha3::Keccak256;
use sandstorm_claims::sharp::input::CairoAuxInput;
use sandstorm_claims::sharp::verifier::SharpMetadata;
use ministark::stark::Stark;
use sandstorm_layouts::starknet::{AirConfig, ExecutionTrace};
use std::io::Write;

// const PROOF_BYTES: &[u8] = include_bytes!("../stark-proof.bin");
// const PROGRAM_BYTES: &[u8] = include_bytes!("../cairo-program.json");
const AIR_PUBLIC_INPUT_BYTES: &[u8] = include_bytes!("../air-public-input.json");
const PROOF_BYTES: &[u8] = include_bytes!("../bootloader-proof.bin");
const PROGRAM_BYTES: &[u8] = include_bytes!("../bootloader_compiled.json");

type SharpClaim = sharp::CairoClaim<AirConfig, ExecutionTrace, Keccak256>;
type SharpProof = Proof<
    <SharpClaim as Stark>::Fp,
    <SharpClaim as Stark>::Fp,
    <SharpClaim as Stark>::Digest,
    <SharpClaim as Stark>::MerkleTree,
>;

fn main() -> std::io::Result<()> {
    let air_public_input: AirPublicInput<Fp> =
        serde_json::from_reader(AIR_PUBLIC_INPUT_BYTES).unwrap();
    let program: CompiledProgram<Fp> = serde_json::from_reader(PROGRAM_BYTES).unwrap();
    let claim = SharpClaim::new(program, air_public_input);
    let proof: SharpProof = Proof::deserialize_compressed(PROOF_BYTES).unwrap();
    let metadata = claim.verify_sharp(proof.clone()).unwrap();

    let mut output = File::create("./test/AutoGenProofData.sol")?;
    write!(output, "{}", gen_proof_data_class(claim, metadata, proof))
}

fn gen_proof_data_class(claim: SharpClaim, metadata: SharpMetadata, proof: SharpProof) -> String {
    let mut res = String::new();

    println!(
        "YOO public memory product: {}",
        metadata.public_memory_quotient
    );

    let public_inputs = claim.get_public_inputs();
    let sharp_public_input = CairoAuxInput(&public_inputs);

    let public_memory_product: BigUint = metadata.public_memory_product.into();
    let public_memory_z: BigUint = metadata.public_memory_z.into();
    let public_memory_alpha: BigUint = metadata.public_memory_alpha.into();

    let cairo_aux_elements = [
        sharp_public_input.public_input_elements::<Keccak256>(),
        vec![
            U256::from(public_memory_product),
            U256::from(public_memory_z),
            U256::from(public_memory_alpha),
        ],
    ]
    .concat();
    let fmt_cairo_aux_inputs = fmt_array_items(&cairo_aux_elements);

    let proof_params = fmt_array_items(&get_proof_params(&proof));

    let mut proof_elements = Vec::new();
    proof_elements.extend_from_slice(&[
        U256::try_from_be_slice(&proof.base_trace_commitment).unwrap(),
        U256::try_from_be_slice(&proof.extension_trace_commitment.unwrap()).unwrap(),
        U256::try_from_be_slice(&proof.composition_trace_commitment).unwrap(),
    ]);
    for eval in proof.execution_trace_ood_evals {
        // proof_elements.push(U256::from(BigUint::from(eval)));
        proof_elements.push(U256::from(to_montgomery(eval)));
    }
    for eval in proof.composition_trace_ood_evals {
        println!("ood eval: {}", eval);
        proof_elements.push(U256::from(to_montgomery(eval)));
    }
    for layer in &proof.fri_proof.layers {
        let commitment = U256::try_from_be_slice(&layer.commitment).unwrap();
        println!("layer commitment is {}", commitment);
        proof_elements.push(commitment);
    }
    let fri_remainder_coeffs = proof.fri_proof.remainder_coeffs;
    println!("Fri remainder coeffs len: {}", fri_remainder_coeffs.len());
    for eval in fri_remainder_coeffs {
        println!("remainder eval: {}", eval);
        proof_elements.push(U256::from(to_montgomery(eval)));
    }
    let shifted_nonce = U256::from(proof.pow_nonce) << (256 - 64);
    proof_elements.push(shifted_nonce);

    let proof_elements = fmt_array_items(&proof_elements);

    res += &format!(
        r"// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.6.12;

contract AutoGenProofData {{
    function getProofParams() public view returns (uint256[] memory) {{
        return proofParams;
    }}

    function getProof() public view returns (uint256[] memory) {{
        return proof;
    }}

    function getTaskMetadata() public view returns (uint256[] memory) {{
        return taskMetadata;
    }}

    function getCairoAuxInput() public view returns (uint256[] memory) {{
        return cairoAuxInput;
    }}

    uint256 public cairoVerifierId = 6;

    uint256[] public proofParams = {proof_params};

    uint256[] public proof = {proof_elements};

    uint256[] public taskMetadata = [0];

    uint256[] public cairoAuxInput = {fmt_cairo_aux_inputs};
}}
",
    );

    res
}

/// Pretty prints a solidity array
fn fmt_array_items(items: &[impl Display]) -> String {
    let mut res = String::new();
    res += "[";
    let num_items = items.len();
    for (i, item) in items.iter().enumerate() {
        if i == num_items - 1 {
            res += &format!("{item}");
        } else {
            res += &format!("{item},");
        }
    }
    res += "]";
    res
}

fn get_proof_params(proof: &SharpProof) -> Vec<U256> {
    let options = proof.options;
    const N_QUERIES_OFFSET: usize = 0;
    const LOG_BLOWUP_FACTOR_OFFSET: usize = 1;
    const PROOF_OF_WORK_BITS_OFFSET: usize = 2;
    const FRI_LAST_LAYER_LOG_DEG_BOUND_OFFSET: usize = 3;
    const N_FRI_STEPS_OFFSET: usize = 4;

    let fri_options = options.into_fri_options();
    // fri_options.max_remainder_size;

    let lde_domain_size = proof.trace_len * options.lde_blowup_factor as usize;
    let folding_factor = U256::from(options.fri_folding_factor.ilog2());
    let fri_steps = [
        vec![uint!(0_U256)],
        vec![folding_factor; fri_options.num_layers(lde_domain_size)],
    ]
    .concat();

    let fri_last_layer_log_deg_bound =
        (fri_options.remainder_size(lde_domain_size) / options.lde_blowup_factor as usize).ilog2();

    let base_vals = {
        const NUM_VALS: usize = N_FRI_STEPS_OFFSET + 1;
        let mut vals = [U256::ZERO; NUM_VALS];
        vals[N_QUERIES_OFFSET] = U256::from(options.num_queries);
        vals[LOG_BLOWUP_FACTOR_OFFSET] = U256::from(options.lde_blowup_factor.ilog2());
        vals[PROOF_OF_WORK_BITS_OFFSET] = U256::from(options.grinding_factor);
        vals[FRI_LAST_LAYER_LOG_DEG_BOUND_OFFSET] = U256::from(fri_last_layer_log_deg_bound);
        vals[N_FRI_STEPS_OFFSET] = U256::from(fri_steps.len());
        vals.to_vec()
    };

    [base_vals, fri_steps].concat()
}
