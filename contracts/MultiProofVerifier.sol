// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

import { MonoVcpGenerationVerifier } from "./MonoVcpGenerationVerifier.sol";
import { Requirement, PublicKeys } from "./util.sol";

contract MultiProofVerifier {
    // name
    string public verifierName;

    // access credential
    Requirement requirement;

    // issuer public keys
    PublicKeys publicKeys;

    // revocation tree roots
    bytes32[] public revocationTreeRoots;

    MonoVcpGenerationVerifier public verifier;

    event OnComparision(uint256 i, uint256 l, uint256 r);
    event OnCondition(uint256 i, uint8 p, uint256 invertedIndex);
    event OnValidation(bool[] arr);

    address payable public owner;

    constructor(string memory _verifierName, MonoVcpGenerationVerifier _verifier, address payable _owner) {
        verifierName = _verifierName;
        verifier = _verifier;
        owner  = _owner;
    }

    function getRevocationTreeRoots() public view returns (bytes32[] memory) {
        return revocationTreeRoots;
    }

    function getRequirement() public view returns (Requirement memory) {
        return requirement;
    }

    function getPublicKeys() public view returns (PublicKeys memory) {
        return publicKeys;
    }

    function updateRequirement(Requirement calldata _requirement, PublicKeys calldata _publicKeys, bytes32[] calldata _revocationTreeRoots) public {
        requirement = _requirement;
        publicKeys = _publicKeys;
        revocationTreeRoots = _revocationTreeRoots;
    }

    function preparePublicInputs(uint8 proofIndex, uint8 provingTime) external view returns (bytes32[] memory) {
        bytes32[] memory _publicInputs = new bytes32[](10);
        _publicInputs[0] = bytes32(requirement.conditions[proofIndex].attrCode);
        _publicInputs[1] = bytes32(abi.encode(requirement.conditions[proofIndex].operator));
        _publicInputs[2] = bytes32(abi.encode(requirement.conditions[proofIndex].value));
        _publicInputs[3] = bytes32(publicKeys.publicKeys[requirement.conditions[proofIndex].issuerIds[0]].issuerCode);

        // publicKeys.publicKeys[requirement.conditions[i].issuerIds[0]].issuerCode
        _publicInputs[4] = bytes32(abi.encode(2));

        _publicInputs[5] = bytes32(publicKeys.publicKeys[requirement.conditions[proofIndex].issuerIds[0]].issuerCode);
        _publicInputs[6] = publicKeys.publicKeys[proofIndex].publicKey.x;
        _publicInputs[7] = publicKeys.publicKeys[proofIndex].publicKey.y;
        _publicInputs[8] = bytes32(abi.encode(provingTime));
        _publicInputs[9] = bytes32(revocationTreeRoots[proofIndex]);

        return _publicInputs;
    }

    function verifyCondition(bytes calldata proof, uint8 proofIndex, uint8 provingTime) external view returns  (bool) {
        bytes32[] memory _publicInputs = this.preparePublicInputs(proofIndex, provingTime);
        return verifier.verify(proof, _publicInputs);
    }

    function getNumPredicates() external view returns (uint256) {
        return requirement.predicates.length;
    }

    function verifyPredicates(bool[] calldata conditionValidations) external view returns (bool) {
        bool[] memory validations = new bool[](requirement.predicates.length);
        // emit OnValidation(validations);

        for(uint256 i = 0; i < requirement.predicates.length; i++){
            uint256 invertedIndex = requirement.predicates.length - 1 - i;
            // emit OnCondition(i, requirement.predicates[i], invertedIndex);
            if (requirement.predicates[invertedIndex] == 0) {
            //     require(i * 2 + 2 < requirement.predicates.length);

                validations[invertedIndex] = validations[invertedIndex * 2 + 1] && validations[invertedIndex * 2 + 2];

            } else if (requirement.predicates[invertedIndex] == 1) {
                validations[invertedIndex] = validations[invertedIndex * 2 + 1] || validations[invertedIndex * 2 + 2];

            } else {
                require(requirement.predicates[invertedIndex] - 2 >= 0);
                require(requirement.predicates[invertedIndex] - 2 < conditionValidations.length);

                validations[invertedIndex] = conditionValidations[requirement.predicates[invertedIndex] - 2];
            }
            // emit OnValidation(validations);
        }

        // emit OnValidation(validations);

        return validations[0];
    }

    function verify(bytes[] calldata _proofs, uint8 _provingTime) external view returns (bool) {
        bool[] memory conditionValidations = this.verifyConditions(_proofs, _provingTime);

        return this.verifyPredicates(conditionValidations);
    }

    function verifyConditions(bytes[] calldata _proofs, uint8 _provingTime) external view returns (bool[] memory) {
        bool[] memory conditionValidations = new bool[](_proofs.length);
        bytes32[] memory _publicInputs;

        for (uint8 i = 0; i < _proofs.length; i++) {
            _publicInputs = this.preparePublicInputs(i, _provingTime);
            conditionValidations[i] = verifier.verify(_proofs[i], _publicInputs);
        }

        return conditionValidations;
    }

    function transfer(bytes[] calldata _proofs, uint8 provingTime, address payable _to) public {
        if (this.verify(_proofs, provingTime)) {
            owner = _to;
        }
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}
