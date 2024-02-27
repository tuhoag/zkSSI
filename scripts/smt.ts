import fs from "fs";
import { mulPointEscalar, r } from "@zk-kit/baby-jubjub";
import { randomBytes } from "crypto";
import { ethers } from "hardhat";
import { ChildNodes, Node, SMT } from "@zk-kit/smt"
import sha256 from "crypto-js/sha256"
import { poseidon2, poseidon3 } from "poseidon-lite"
import { toBigInt } from "ethers";
import { expect } from "chai";
import { poseidonEncrypt, poseidonDecrypt, poseidonDecryptWithoutCheck } from "@zk-kit/poseidon-cipher"
// import schnorr from "@noir-lang/barretenberg/crypto/schnorr";
import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { Schnorr } from '@noir-lang/barretenberg/dest/crypto/schnorr';
import {
    derivePublicKey,
    signMessage,
    verifySignature,
    deriveSecretScalar,
    packPublicKey,
    unpackPublicKey
} from "@zk-kit/eddsa-poseidon"
import path from "path";

import claims from "../data/claims.json";


async function main() {
    const hash = (childNodes: ChildNodes) => {
        console.log(childNodes.length);
        console.log(childNodes);
        let hashed_value: any;

        if (childNodes.length % 2 == 0) {
            hashed_value = poseidon2(childNodes)
        } else {
            hashed_value = poseidon3(childNodes);
        }

        console.log(hashed_value);
        return hashed_value;
    };

    const tree = new SMT(hash, true)
    const oldRoot = tree.root

    console.log(oldRoot)

    tree.add(BigInt(2), BigInt(14))
    tree.add(BigInt(3), BigInt(15))

    expect(tree.root).not.equal(oldRoot);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
