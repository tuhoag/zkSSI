import fs from "fs";
import { mulPointEscalar, r } from "@zk-kit/baby-jubjub";
import { randomBytes } from "crypto";
import { ethers } from "hardhat";
import { ChildNodes, Node, SMT } from "@zk-kit/smt"
import sha256 from "crypto-js/sha256"
import { poseidon1, poseidon2, poseidon3, poseidon5 } from "poseidon-lite"
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
import { NoirProgram } from "./utils";


async function main() {
    const program = await NoirProgram.createProgram("vc_presentation_generation", { threads: 8 });

    const inputs = {
        criteria: {
            conditions: [
                {
                    name: "birth_day ",
                    operator: "> ",
                    value: 18,
                    issuer: "issuer00",
                },
                {
                    name: "birth_day ",
                    operator: "> ",
                    value: 18,
                    issuer: "issuer00",
                }
            ],
            combinations: ["&"],
        },
        credential: {
            claims: [
                {
                    name: "birth_day ",
                    value: 19,
                    issuer: "issuer00",
                },
                {
                    name: "birth_day ",
                    value: 19,
                    issuer: "issuer00",
                },
            ]
        }
    }

    const proof = await program.prove(inputs);
    console.log(proof);

    const verification = await program.verify(proof);
    console.log(verification);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
