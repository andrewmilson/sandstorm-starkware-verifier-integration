// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.2; // test
pragma experimental ABIEncoderV2;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/verifier/CpuConstraintPoly.sol";
import "../src/periodic_columns/PoseidonPoseidonFullRoundKey0Column.sol";
import "../src/periodic_columns/PoseidonPoseidonFullRoundKey1Column.sol";
import "../src/periodic_columns/PoseidonPoseidonFullRoundKey2Column.sol";
import "../src/periodic_columns/PoseidonPoseidonPartialRoundKey0Column.sol";
import "../src/periodic_columns/PoseidonPoseidonPartialRoundKey1Column.sol";
import "../src/periodic_columns/EcdsaPointsXColumn.sol";
import "../src/periodic_columns/EcdsaPointsYColumn.sol";
import "../src/periodic_columns/PedersenHashPointsXColumn.sol";
import "../src/periodic_columns/PedersenHashPointsYColumn.sol";
import "../src/gps/CairoBootloaderProgram.sol";
import "../src/verifier/FriStatementVerifier.sol";
import "../src/verifier/CpuFrilessVerifier.sol";
import "../src/MemoryPageFactRegistry.sol";
import "../src/verifier/FriStatementContract.sol";
import "../src/verifier/VerifierChannel.sol";
import "../src/CpuOods.sol";
import "../src/gps/GpsStatementVerifier.sol";
import "./ProofData.sol";
import "./AutoGenProofData.sol";

contract StarkNetVerifierTest is Test {
    // == CPU layout6 verifier ==
    // https://etherscan.io/address/0xe9664d230490d5a515ef7ef30033d8075a8d0e24#code
    uint256 numSecurityBits = 96;
    // uint256 numSecurityBits = 30;
    uint256 minProofOfWorkBits = 30;
    // uint256 minProofOfWorkBits = 8;
    CpuConstraintPoly public cpuConstraintPoly;
    PedersenHashPointsXColumn pedersenPointsX;
    PedersenHashPointsYColumn pedersenPointsY;
    EcdsaPointsXColumn ecdsaPointsX;
    EcdsaPointsYColumn ecdsaPointsY;
    PoseidonPoseidonFullRoundKey0Column poseidonPoseidonFullRoundKey0Column;
    PoseidonPoseidonFullRoundKey1Column poseidonPoseidonFullRoundKey1Column;
    PoseidonPoseidonFullRoundKey2Column poseidonPoseidonFullRoundKey2Column;
    PoseidonPoseidonPartialRoundKey0Column poseidonPoseidonPartialRoundKey0Column;
    PoseidonPoseidonPartialRoundKey1Column poseidonPoseidonPartialRoundKey1Column;
    address[] public auxPolynomials;
    MemoryPageFactRegistry public memoryPageFactRegistry;
    MerkleStatementContract public merkleStatementContract;
    FriStatementContract public friStatementContract;
    FriStatementVerifier public friStatementVerifier;
    CpuOods cpuOods;
    CpuFrilessVerifier public cpuFrilessVerifier;

    // == GPS statement verifier ==
    // https://etherscan.io/address/0x6cB3EE90C50a38A0e4662bB7e7E6e40B91361BF6#code
    CairoBootloaderProgram public bootloaderProgram;
    address[] public cairoVerifierContracts;
    uint256 hashedSupportedCairoVerifiers;
    uint256 simpleBootloaderProgramHash;
    GpsStatementVerifier public gpsStatementVerifier;

    function setUp() public {
        // TODO: find out what the MemoryPageFactRegistry does
        memoryPageFactRegistry = new MemoryPageFactRegistry();
        merkleStatementContract = new MerkleStatementContract();
        friStatementContract = new FriStatementContract();
        cpuOods = new CpuOods();
        // TODO: find the coefficients for this polynomial
        cpuConstraintPoly = new CpuConstraintPoly();
        pedersenPointsX = new PedersenHashPointsXColumn();
        pedersenPointsY = new PedersenHashPointsYColumn();
        ecdsaPointsX = new EcdsaPointsXColumn();
        ecdsaPointsY = new EcdsaPointsYColumn();
        poseidonPoseidonFullRoundKey0Column = new PoseidonPoseidonFullRoundKey0Column();
        poseidonPoseidonFullRoundKey1Column = new PoseidonPoseidonFullRoundKey1Column();
        poseidonPoseidonFullRoundKey2Column = new PoseidonPoseidonFullRoundKey2Column();
        poseidonPoseidonPartialRoundKey0Column = new PoseidonPoseidonPartialRoundKey0Column();
        poseidonPoseidonPartialRoundKey1Column = new PoseidonPoseidonPartialRoundKey1Column();
        auxPolynomials = [
            address(cpuConstraintPoly),
            address(pedersenPointsX),
            address(pedersenPointsY)
        ];
        cpuFrilessVerifier = new CpuFrilessVerifier(
            auxPolynomials,
            address(cpuOods),
            address(memoryPageFactRegistry),
            address(merkleStatementContract),
            address(friStatementContract),
            numSecurityBits,
            minProofOfWorkBits
        );

        bootloaderProgram = new CairoBootloaderProgram();
        // TODO: what are these? Maybe ask Starkware for the pre-images
        // hashedSupportedCairoVerifiers = 3178097804922730583543126053422762895998573737925004508949311089390705597156;
        hashedSupportedCairoVerifiers = 37341341331504021525228390428349719127283617351070997452015539964478373189;
        simpleBootloaderProgramHash = 2962621603719000361370283216422448934312521782617806945663080079725495842070;
        // TODO: in reality these addresses map to different verifiers
        // For the sake of simplicity have the same amount of verifiers
        // as the on-chain contract but have them be all the same address
        cairoVerifierContracts = [
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier),
            address(cpuFrilessVerifier)
        ];
        gpsStatementVerifier = new GpsStatementVerifier(
            address(bootloaderProgram),
            address(memoryPageFactRegistry),
            cairoVerifierContracts,
            hashedSupportedCairoVerifiers,
            simpleBootloaderProgramHash
        );
    }

    // function testAddMerkleStatement() public {
    //     AutoGenProofData proofData = new AutoGenProofData();
    //     MerkleStatementContract myMerkleContract = new MerkleStatementContract();
    //     myMerkleContract.verifyMerkle(
    //         proofData.getBaseTraceMerkleView(),
    //         proofData.getBaseTraceMerkleInitials(),
    //         proofData.baseTraceMerkleHeight(),
    //         proofData.baseTraceMerkleRoot()
    //     );
    // }

    // function testFriStatement() public {
    //     AutoGenProofData proofData = new AutoGenProofData();
    //     FriDataLayer firstStatement = proofData.getFriDataLayers()[0];
    //     FriStatementContract myFriContract = new FriStatementContract();
    //     myFriContract.verifyFRI(
    //         firstStatement.getProof(),
    //         firstStatement.getQueue(),
    //         firstStatement.evalPoint(),
    //         firstStatement.stepSize(),
    //         firstStatement.root()
    //     );
    // }

    function testVerify() public {
        // ProofData proofData = new ProofData();
        AutoGenProofData proofData = new AutoGenProofData();
        uint256 cairoVerifierId = proofData.cairoVerifierId();
        console.logUint(proofData.cairoVerifierId());
        console.log(address(bootloaderProgram));

        // register merkle statements
        // 1. base trace
        merkleStatementContract.verifyMerkle(
            proofData.getBaseTraceMerkleView(),
            proofData.getBaseTraceMerkleInitials(),
            proofData.baseTraceMerkleHeight(),
            proofData.baseTraceMerkleRoot()
        );
        // 2. extension trace
        merkleStatementContract.verifyMerkle(
            proofData.getExtensionTraceMerkleView(),
            proofData.getExtensionTraceMerkleInitials(),
            proofData.extensionTraceMerkleHeight(),
            proofData.extensionTraceMerkleRoot()
        );
        // 2. composition trace
        merkleStatementContract.verifyMerkle(
            proofData.getCompositionTraceMerkleView(),
            proofData.getCompositionTraceMerkleInitials(),
            proofData.compositionTraceMerkleHeight(),
            proofData.compositionTraceMerkleRoot()
        );

        // register fri layer statements
        FriDataLayer[] memory friDataLayers = proofData.getFriDataLayers();
        for (uint i = 0; i < friDataLayers.length; i++) {
            console.log("verifying fri layer", i);
            FriDataLayer friDataLayer = friDataLayers[i];
            friStatementContract.verifyFRI(
                friDataLayer.getProof(),
                friDataLayer.getQueue(),
                friDataLayer.evalPoint(),
                friDataLayer.stepSize(),
                friDataLayer.root()
            );
        }

        gpsStatementVerifier.verifyProofAndRegister(
            proofData.getProofParams(),
            proofData.getProof(),
            proofData.getTaskMetadata(),
            proofData.getCairoAuxInput(),
            proofData.cairoVerifierId()
        );
    }
}
