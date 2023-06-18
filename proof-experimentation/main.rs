use std::{fmt::Display, fs::File, path::Path};

use ark_serialize::CanonicalDeserialize;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ministark::Proof;
use num_bigint::BigUint;
use sandstorm_binary::CompiledProgram;
use std::io::Write;
use ark_ff::Field;
use sandstorm_layouts::starknet::AirConfig;

const PROOF_BYTES: &[u8] = include_bytes!("../stark-proof.bin");
const PROGRAM_BYTES: &[u8] = include_bytes!("../cairo-program.json");

struct ProofArtifacts {
    memory_alpha: Fp,
    memory_z: Fp,
    program: CompiledProgram,
    cairo_aux_input: Vec<Fp>,
}

fn main() -> std::io::Result<()> {
    let program: CompiledProgram = serde_json::from_reader(PROGRAM_BYTES).unwrap();
    let proof: Proof<AirConfig> = Proof::deserialize_compressed(PROOF_BYTES).unwrap();
    let artifacts = generate_artifacts(program, proof);

    let mut output = File::create("./test/AutoGenProofData.sol")?;
    write!(output, "{}", gen_proof_data_class(artifacts))
}

fn generate_artifacts(program: CompiledProgram, proof: Proof<AirConfig>) -> ProofArtifacts {
    let mut artifacts = ProofArtifacts {
        program,
        memory_alpha: Fp::ONE,
        memory_z: Fp::ONE,
        cairo_aux_input: proof.public_inputs.serialise_sharp(),
    };

    artifacts
}

fn gen_proof_data_class(artifacts: ProofArtifacts) -> String {
    let mut res = String::new();

    let fmt_cairo_aux_inputs = fmt_array_items(
        &artifacts
            .cairo_aux_input
            .into_iter()
            .map(BigUint::from)
            .collect::<Vec<_>>(),
    );

    let fmt_program_felts = fmt_array_items(&artifacts.program.data);

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

    uint256[] public proofParams = [0];

    uint256[] public proof = [0];

    uint256[] public taskMetadata = [0];

    uint256[] public cairoAuxInput = {fmt_cairo_aux_inputs};

    uint256[] public program = {fmt_program_felts};
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
