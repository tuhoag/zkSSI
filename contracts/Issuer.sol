// // SPDX-License-Identifier: GPL-3.0
// pragma solidity 0.8.24;

// // import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

// contract Issuer {
//   bytes32 public merkleRoot;

//   constructor(bytes32 _merkleRoot) {
//     merkleRoot = _merkleRoot;
//   }

//   function claim(bytes32[] memory proof, address account) public {
//     bytes32 leaf = keccak256(abi.encodePacked(account));
//     require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");

//     // User is in the whitelist, allow them to claim the NFT

//   }
// }
