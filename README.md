# Generate and serialise proof

```bash
# compile and run the bootloader
cairo-run --program_input ./bootloader_inputs.json \
    --program ./bootloader_compiled.json \
    --air_private_input ./air-private-input.json \
    --air_public_input ./air-public-input.json \
    --trace_file ./trace.bin \
    --memory_file ./memory.bin \
    --layout starknet \
    --min_steps 128 \
    --proof_mode \
    --print_info

# install sandstorm-cli
cargo +nightly install --features parallel --git https://github.com/andrewmilson/sandstorm sandstorm-cli

# generate the proof
sandstorm-cli --program bootloader_compiled.json --air-public-input air-public-input.json
sandstorm-cli --program bootloader_compiled.json \
    --air-public-input air-public-input.json \
    prove --lde-blowup-factor 4 --num-queries 33 --proof-of-work-bits 30 --air-private-input air-private-input.json \
          --output bootloader-proof.bin &&  && forge test -vv

# run the program in proof-experimentation/main.rs
# it generates test/AutoGenProofData.sol which has everything you need to plug into the contract inputs
cargo run

# can test locally to make sure the solidity verifyProof() works
forge test -vv
```

<!-- ## Questions

What is `taskMetadata`? [CpuVerifier.sol](src/gps/GpsStatementVerifier.sol#L199)


```bash
# compile
cairo-compile ~/projects/cairo-lang-bootloader-testing/src/starkware/cairo/bootloaders/bootloader/bootloader.cairo --proof_mode --debug_info_with_source --output bootloader_compiled.json --cairo_path ~/projects/cairo-lang-bootloader-testing/src

# run
cairo-run --program_input ./bootloader_inputs.json --program bootloader_compiled.json \
          --air_private_input ./air-private-input.json \
          --air_public_input ./air-public-input.json \
          --trace_file ./trace.bin \
          --memory_file ./memory.bin \
          --layout starknet \
          --min_steps 128 \
          --proof_mode --print_info


../sandstorm/target/release/sandstorm --program bootloader_compiled.json --layout starknet \
    --air-public-input air-public-input.json \
    prove --air-private-input air-private-input.json \
          --output bootloader-proof.bin
``` -->
## Test
To test it on a testnet like Sepolia,
- First upload all your contracts to [Remix](https://remix.ethereum.org/)
  
  <img width="1470" alt="image" src="https://github.com/andrewmilson/sandstorm-starkware-verifier-integration/assets/44467788/21a42f13-246d-4220-a490-1f2f3b08ba80">
- Then compile your required solidity file with the required compiler version

  <img width="367" alt="image" src="https://github.com/andrewmilson/sandstorm-starkware-verifier-integration/assets/44467788/a3ebe738-4fb7-472f-b852-570b810bf05f">
- Deploy using your injected provider on your required chain

  <img width="358" alt="image" src="https://github.com/andrewmilson/sandstorm-starkware-verifier-integration/assets/44467788/05acaf71-98e6-4d12-a3d2-e7f114a45d02">
- On deployment, you'll get the address of your contract for you to interact with it

  

