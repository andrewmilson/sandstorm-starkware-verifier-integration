// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.6.12;

contract AutoGenProofData {
    function getProofParams() public view returns (uint256[] memory) {
        return proofParams;
    }

    function getProof() public view returns (uint256[] memory) {
        return proof;
    }

    function getTaskMetadata() public view returns (uint256[] memory) {
        return taskMetadata;
    }

    function getCairoAuxInput() public view returns (uint256[] memory) {
        return cairoAuxInput;
    }

    uint256 public cairoVerifierId = 6;

    uint256[] public proofParams = [40,1,16,3,7,0,3,3,3,3,3,3];

    uint256[] public proof = [0];

    uint256[] public taskMetadata = [0];

    uint256[] public cairoAuxInput = [17,32758,32793,8319381555716711796,1,5,569,1177,1177,1180,1180,1186,13468,13468,21660,21660,21788,21788,32028,32028,32924,32924,1,290341444919459839,1,587,8048704624329011195936709297904314376750662390639924589948177687335394336756,2620804158712819753812379964219983648301541326536097327392954495826687185263,2409540386577024674588489514924948308524161399144808749199313447479267084532,2645682141694054602817202056379044791623667285527122690217077542203312395363];
}
