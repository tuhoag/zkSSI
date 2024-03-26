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

    constructor(string memory _verifierName, MonoVcpGenerationVerifier _verifier) {
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

    function preparePublicInputs(uint8 provingTime, uint8 conditionIndex) external view returns (bytes32[] memory) {
        bytes32[] memory _publicInputs = new bytes32[](10);
        _publicInputs[0] = bytes32(requirement.conditions[conditionIndex].attrCode);
        _publicInputs[1] = bytes32(abi.encode(requirement.conditions[conditionIndex].operator));
        _publicInputs[2] = bytes32(abi.encode(requirement.conditions[conditionIndex].value));
        _publicInputs[3] = bytes32(requirement.conditions[conditionIndex].issuerCodes[0]);
        _publicInputs[4] = bytes32(abi.encode(2));

        _publicInputs[5] = bytes32(publicKeys.publicKeys[conditionIndex].issuerCode);
        _publicInputs[6] = publicKeys.publicKeys[conditionIndex].publicKey.x;
        _publicInputs[7] = publicKeys.publicKeys[conditionIndex].publicKey.y;
        _publicInputs[8] = bytes32(abi.encode(provingTime));
        _publicInputs[9] = bytes32(revocationTreeRoots[conditionIndex]);

        return _publicInputs;
    }

    function verifyCondition(bytes calldata proof, uint8 provingTime, uint8 conditionIndex) external view returns  (bool) {
        bytes32[] memory _publicInputs = this.preparePublicInputs(provingTime, conditionIndex);
        return verifier.verify(proof, _publicInputs);
    }

    function verifyConditions(bytes[] calldata proofs, uint8 provingTime) external view returns (bool[] memory) {
        bool[] memory conditionValidations = new bool[](proofs.length);
        bytes32[] memory _publicInputs;
        //  = this.preparePublicInputs(provingTime, 0);
        // conditionValidations[0] = verifier.verify(proofs[0], _publicInputs);

        for (uint8 i = 0; i < proofs.length; i++) {
            _publicInputs = this.preparePublicInputs(provingTime, i);
            conditionValidations[i] = verifier.verify(proofs[i], _publicInputs);
        }

        return conditionValidations;
    }


    function getNumPredicates() external view returns (uint256) {
        return requirement.predicates.length;
    }

    function verifyPredicates(bool[] calldata conditionValidations) external view returns (bool) {
        bool[] memory validations = new bool[](requirement.predicates.length);
        // emit OnValidation(validations);

        // for (uint256 i = requirement.predicates.length - 1; i >= 0; i--) {
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

    function verify(bytes[] calldata proofs, uint8 provingTime) external view returns (bool) {
        bool[] memory conditionValidations = this.verifyConditions(proofs, provingTime);

        return this.verifyPredicates(conditionValidations);
    }
}
