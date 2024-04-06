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

    address payable public owner;

    constructor(string memory _verifierName, VcpGenerationVerifier _verifier, address payable _owner) {
        verifierName = _verifierName;
        verifier = _verifier;
        owner = _owner;
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

    function getNumberOfPublicInputs() external view returns (uint256) {
        return requirement.conditions.length * 10;
    }

    function preparePublicInputs(uint8 provingTime) external view returns (bytes32[] memory) {
        uint256 numPublicInputs = this.getNumberOfPublicInputs();
        bytes32[] memory _publicInputs = new bytes32[](numPublicInputs);
        uint256 curIndex = 0;

        for (uint256 i = 0; i < requirement.conditions.length; i++) {
            // uint8 issuerId =requirement.conditions[i].issuerIds[0];

            _publicInputs[curIndex] = bytes32(requirement.conditions[i].attrCode);
            _publicInputs[curIndex + 1] = bytes32(abi.encode(requirement.conditions[i].operator));
            _publicInputs[curIndex + 2] = bytes32(abi.encode(requirement.conditions[i].value));
            _publicInputs[curIndex + 3] = publicKeys.publicKeys[requirement.conditions[i].issuerIds[0]].issuerCode;

            curIndex = curIndex + 4;
        }

        for (uint256 i = 0; i < requirement.predicates.length; i++) {
            _publicInputs[curIndex] = bytes32(abi.encode(requirement.predicates[i]));
            curIndex = curIndex + 1;
        }

        for (uint256 i = 0; i < publicKeys.publicKeys.length; i++) {
            _publicInputs[curIndex] = bytes32(publicKeys.publicKeys[i].issuerCode);
            _publicInputs[curIndex + 1] = publicKeys.publicKeys[i].publicKey.x;
            _publicInputs[curIndex + 2] = publicKeys.publicKeys[i].publicKey.y;

            curIndex = curIndex + 3;
        }

        _publicInputs[curIndex] = bytes32(abi.encode(provingTime));
        curIndex = curIndex + 1;


        for (uint256 i = 0; i < revocationTreeRoots.length; i++) {
            _publicInputs[curIndex] = bytes32(revocationTreeRoots[i]);

            curIndex = curIndex + 1;
        }

        return _publicInputs;
    }

    function verify(bytes calldata proof, uint8 provingTime) external view returns (bool) {
        bytes32[] memory _publicInputs = this.preparePublicInputs(provingTime);

        return verifier.verify(proof, _publicInputs);
    }

    function transfer(bytes calldata proof, uint8 provingTime, address payable _to) public {
        if (this.verify(proof, provingTime)) {
            owner = _to;
        }
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}
