use std::iter::zip;
use std::{fmt::Display, fs::File, path::Path};

mod batched_merkle;

use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use batched_merkle::{BatchedMerkleProof, MerkleProofsVariant};
use ministark::merkle::{MerkleTreeConfig, HashedLeafConfig};
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ministark::{Proof, merkle::MerkleProof};
use ministark::air::AirConfig as _;
use num_bigint::BigUint;
use ruint::{aliases::U256, uint};
use sandstorm_claims::sharp::merkle::MerkleTreeVariantProof;
use sandstorm_claims::sharp::utils::to_montgomery;
use sandstorm_binary::{CompiledProgram, AirPublicInput};
use sandstorm_claims::sharp;
use sha2::Digest;
use sha2::digest::Output;
use sha3::Keccak256;
use sandstorm_claims::sharp::input::CairoAuxInput;
use sandstorm_claims::sharp::verifier::SharpMetadata;
use ministark::stark::Stark;
use sandstorm_layouts::starknet::{AirConfig, ExecutionTrace};
use std::io::Write;

use crate::batched_merkle::partition_proofs;

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
        U256::try_from_be_slice(proof.extension_trace_commitment.as_ref().unwrap()).unwrap(),
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

    let mut remainder_bytes = Vec::new();

    remainder_bytes.extend(proof.pow_nonce.to_be_bytes());

    // let shifted_nonce = U256::from(proof.pow_nonce) << (256 - 64);
    // proof_elements.push(shifted_nonce);

    // let base_trace_rows = proof
    //     .trace_queries
    //     .base_trace_values
    //     .chunks(AirConfig::NUM_BASE_COLUMNS)
    //     .collect::<Vec<_>>();

    println!(
        "first item: {}",
        U256::from(to_montgomery(proof.trace_queries.base_trace_values[0]))
    );

    for val in proof.trace_queries.base_trace_values {
        remainder_bytes.extend(U256::from(to_montgomery(val)).to_be_bytes::<32>());
    }
    for val in proof.trace_queries.extension_trace_values {
        remainder_bytes.extend(U256::from(to_montgomery(val)).to_be_bytes::<32>());
    }
    for val in proof.trace_queries.composition_trace_values {
        remainder_bytes.extend(U256::from(to_montgomery(val)).to_be_bytes::<32>());
    }

    let remainder_elements = remainder_bytes
        .chunks(32)
        .map(|chunk| {
            let mut bytes32 = [0u8; 32];
            bytes32[0..chunk.len()].copy_from_slice(chunk);
            U256::try_from_be_slice(&bytes32).unwrap()
        })
        .collect::<Vec<_>>();

    println!("items len: {}", remainder_elements.len());

    proof_elements.extend(remainder_elements);

    // for val in proof.trace_queries.extension_trace_values {
    //     proof_elements.push(U256::from::<BigUint>(val.into()))
    // }

    let proof_elements = fmt_array_items(&proof_elements);

    let base_trace_merkle_proofs = partition_proofs(&proof.trace_queries.base_trace_proofs);
    let base_trace_merkle_statement = get_merkle_statement_values(
        &proof.base_trace_commitment,
        &base_trace_merkle_proofs,
        &metadata.query_positions,
    );
    let base_trace_merkle_view = fmt_array_items(&base_trace_merkle_statement.view);
    let base_trace_initials = base_trace_merkle_statement
        .initials
        .into_iter()
        .flat_map(|(idx, hash)| [U256::from(idx), hash])
        .collect::<Vec<_>>();
    let base_trace_merkle_initials = fmt_array_items(&base_trace_initials);
    let base_trace_merkle_height = base_trace_merkle_statement.height;
    let base_trace_merkle_root = base_trace_merkle_statement.root;

    let extension_trace_merkle_proofs =
        partition_proofs(&proof.trace_queries.extension_trace_proofs);
    let extension_trace_merkle_statement = get_merkle_statement_values(
        proof.extension_trace_commitment.as_ref().as_ref().unwrap(),
        &extension_trace_merkle_proofs,
        &metadata.query_positions,
    );
    let extension_trace_merkle_view = fmt_array_items(&extension_trace_merkle_statement.view);
    let extension_trace_initials = extension_trace_merkle_statement
        .initials
        .into_iter()
        .flat_map(|(idx, hash)| [U256::from(idx), hash])
        .collect::<Vec<_>>();
    let extension_trace_merkle_initials = fmt_array_items(&extension_trace_initials);
    let extension_trace_merkle_height = extension_trace_merkle_statement.height;
    let extension_trace_merkle_root = extension_trace_merkle_statement.root;

    let composition_trace_merkle_proofs =
        partition_proofs(&proof.trace_queries.composition_trace_proofs);
    let composition_trace_merkle_statement = get_merkle_statement_values(
        &proof.composition_trace_commitment,
        &composition_trace_merkle_proofs,
        &metadata.query_positions,
    );
    let composition_trace_merkle_view = fmt_array_items(&composition_trace_merkle_statement.view);
    let composition_trace_initials = composition_trace_merkle_statement
        .initials
        .into_iter()
        .flat_map(|(idx, hash)| [U256::from(idx), hash])
        .collect::<Vec<_>>();
    let composition_trace_merkle_initials = fmt_array_items(&composition_trace_initials);
    let composition_trace_merkle_height = composition_trace_merkle_statement.height;
    let composition_trace_merkle_root = composition_trace_merkle_statement.root;

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

    function getBaseTraceMerkleView() public view returns (uint256[] memory) {{
        return baseTraceMerkleView;
    }}

    function getBaseTraceMerkleInitials() public view returns (uint256[] memory) {{
        return baseTraceMerkleInitials;
    }}

    function getExtensionTraceMerkleView() public view returns (uint256[] memory) {{
        return extensionTraceMerkleView;
    }}

    function getExtensionTraceMerkleInitials() public view returns (uint256[] memory) {{
        return extensionTraceMerkleInitials;
    }}

    function getCompositionTraceMerkleView() public view returns (uint256[] memory) {{
        return compositionTraceMerkleView;
    }}

    function getCompositionTraceMerkleInitials() public view returns (uint256[] memory) {{
        return compositionTraceMerkleInitials;
    }}

    uint256 public cairoVerifierId = 6;

    uint256[] public proofParams = {proof_params};

    uint256[] public proof = {proof_elements};

    uint256[] public taskMetadata = [0];

    uint256[] public cairoAuxInput = {fmt_cairo_aux_inputs};

    uint256[] public baseTraceMerkleView = {base_trace_merkle_view};

    uint256[] public baseTraceMerkleInitials = {base_trace_merkle_initials};

    uint256 public baseTraceMerkleHeight = {base_trace_merkle_height};

    uint256 public baseTraceMerkleRoot = {base_trace_merkle_root};

    uint256[] public extensionTraceMerkleView = {extension_trace_merkle_view};

    uint256[] public extensionTraceMerkleInitials = {extension_trace_merkle_initials};

    uint256 public extensionTraceMerkleHeight = {extension_trace_merkle_height};

    uint256 public extensionTraceMerkleRoot = {extension_trace_merkle_root};

    uint256[] public compositionTraceMerkleView = {composition_trace_merkle_view};

    uint256[] public compositionTraceMerkleInitials = {composition_trace_merkle_initials};

    uint256 public compositionTraceMerkleHeight = {composition_trace_merkle_height};

    uint256 public compositionTraceMerkleRoot = {composition_trace_merkle_root};
}}
",
    );

    res
}

// NOTE: appears a merkle statement looks like this:
// `keccak(idx0 || leaf0 || idx1 || leaf1 || ... || root)`

struct BatchMerkleProofValues {
    root: U256,
    view: Vec<U256>,
    initials: Vec<(usize, U256)>,
    height: usize,
}

fn get_merkle_statement_values<D: Digest + Send + Sync + 'static>(
    root: &Output<D>,
    proofs: &MerkleProofsVariant<D>,
    indices: &[usize],
) -> BatchMerkleProofValues {
    let nodes: Vec<SerdeOutput<D>>;
    let height: usize;
    let mut leaf_siblings = Vec::new();
    let mut initial_leaves = Vec::new();
    match proofs {
        MerkleProofsVariant::Hashed(proofs) => {
            let batch_proof = BatchedMerkleProof::from_proofs(proofs, indices);
            height = batch_proof.height;
            nodes = batch_proof.nodes;
            for leaf in batch_proof.initial_leaves {
                initial_leaves.push(U256::try_from_be_slice(&leaf).unwrap())
            }
            for sibling in batch_proof.sibling_leaves {
                leaf_siblings.push(U256::try_from_be_slice(&sibling).unwrap())
            }
        }
        MerkleProofsVariant::Unhashed(proofs) => {
            let batch_proof = BatchedMerkleProof::from_proofs(proofs, indices);
            height = batch_proof.height;
            nodes = batch_proof.nodes;
            for leaf in batch_proof.initial_leaves {
                let num = to_montgomery(leaf);
                initial_leaves.push(U256::from(num))
            }
            for sibling in batch_proof.sibling_leaves {
                let num = to_montgomery(sibling);
                leaf_siblings.push(U256::from(num))
            }
        }
    }

    let nodes = nodes
        .into_iter()
        .map(|digest| U256::try_from_be_slice(&digest).unwrap())
        .collect::<Vec<U256>>();

    let shift = 1 << height;
    let adjusted_indices = indices.iter().map(|i| i + shift);

    BatchMerkleProofValues {
        root: U256::try_from_be_slice(root).unwrap(),
        view: [leaf_siblings, nodes].concat(),
        initials: zip(adjusted_indices, initial_leaves).collect(),
        height,
    }
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
