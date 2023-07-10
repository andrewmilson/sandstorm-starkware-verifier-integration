import json

f = open('bootloader_compiled.json')
compiled_program = json.load(f)

program = [int(v, 0) for v in compiled_program['data']]
program_size = len(program)

bootloader = f"""// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.6.12;

contract CairoBootloaderProgramSize {{
    uint256 internal constant PROGRAM_SIZE = {program_size};
}}

contract CairoBootloaderProgram is CairoBootloaderProgramSize {{
    function getCompiledProgram()
        external
        pure
        returns (uint256[PROGRAM_SIZE] memory)
    {{
        return {program};
    }}
}}
// ---------- End of auto-generated code. ----------
"""

print(bootloader)

# Closing file
f.close()
