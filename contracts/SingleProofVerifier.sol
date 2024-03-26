// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

import { VcpGenerationVerifier } from "./VcpGenerationVerifier.sol";
import { Requirement, PublicKeys } from "./util.sol";

contract SingleProofVerifier {
    // name
    string public verifierName;

    // access credential
    Requirement requirement;

    // issuer public keys
    PublicKeys publicKeys;

    // revocation tree roots
    bytes32[] public revocationTreeRoots;

    VcpGenerationVerifier public verifier;

    constructor(string memory _verifierName, VcpGenerationVerifier _verifier) {
        verifierName = _verifierName;
        verifier = _verifier;
    }

    function getRevocationTreeRoots() public view returns (bytes32[] memory) {
        return revocationTreeRoots;
    }

    function getRequirement() public view returns (Requirement memory) {
        return requirement;
    }

    function updateRequirement(Requirement calldata _requirement, PublicKeys calldata _publicKeys, bytes32[] calldata _revocationTreeRoots) public {
        requirement = _requirement;
        publicKeys = _publicKeys;
        revocationTreeRoots = _revocationTreeRoots;
    }

    function preparePublicInputs(uint8 provingTime) external view returns (bytes32[] memory) {
        bytes32[] memory _publicInputs = new bytes32[](10);
        _publicInputs[0] = bytes32(requirement.conditions[0].attrCode);
        _publicInputs[1] = bytes32(abi.encode(requirement.conditions[0].operator));
        _publicInputs[2] = bytes32(abi.encode(requirement.conditions[0].value));
        _publicInputs[3] = bytes32(requirement.conditions[0].issuerCodes[0]);
        _publicInputs[4] = bytes32(abi.encode(requirement.predicates[0]));

        _publicInputs[5] = bytes32(publicKeys.publicKeys[0].issuerCode);
        _publicInputs[6] = publicKeys.publicKeys[0].publicKey.x;
        _publicInputs[7] = publicKeys.publicKeys[0].publicKey.y;
        _publicInputs[8] = bytes32(abi.encode(provingTime));
        _publicInputs[9] = bytes32(revocationTreeRoots[0]);

        return _publicInputs;
    }

    function verify(bytes calldata proof, uint8 provingTime) external view returns (bool) {
        bytes32[] memory _publicInputs = this.preparePublicInputs(provingTime);

        return verifier.verify(proof, _publicInputs);
    }
}
