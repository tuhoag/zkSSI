import { NoirProgram } from "./utils";
import circomjs from "circomlibjs";
import {
    derivePublicKey,
    signMessage,
    verifySignature,
    deriveSecretScalar,
    packPublicKey,
    unpackPublicKey
} from "@zk-kit/eddsa-poseidon";

import { poseidon1, poseidon2, poseidon3, poseidon5 } from "poseidon-lite";
import { sign } from "crypto";

function convertIntToHexString(data: number | string | bigint) {
    return `0x${BigInt(data).toString(16)}`;
}

async function main() {
    const program = await NoirProgram.createProgram("test", { threads: 8 });

    const message = [1,2];
    const privateKey = "secret";
    const publicKey = derivePublicKey(privateKey);
    // console.log(`public key: ${publicKey}`);

    const hash = poseidon2(message);
    // console.log(hash);
    const signature = signMessage(privateKey, hash);
    // console.log(signature);
    let inputs = {
        message,
        public_key: {
            x: publicKey[0],
            y: publicKey[1],
        },
        hash: `0x${hash.toString(16)}`,
        signature: {
            s: signature["S"],
            r8_x: signature["R8"][0],
            r8_y: signature["R8"][1],
        }
    }

    let hexInputs = {
        message: [convertIntToHexString(message[0]), convertIntToHexString(message[1])],
        public_key: {
            x: convertIntToHexString(publicKey[0]),
            y: convertIntToHexString(publicKey[1]),
        },
        hash: convertIntToHexString(hash),
        signature: {
            s: convertIntToHexString(signature["S"]),
            r8_x: convertIntToHexString(signature["R8"][0]),
            r8_y: convertIntToHexString(signature["R8"][1]),
        }
    }

    console.log(inputs);
    console.log(hexInputs);

    const proof = await program.prove(hexInputs);
    console.log(proof);
    // const circuitHash = proof.publicInputs[1];
    // const bigIntCircuitHash = BigInt(circuitHash);
    // console.log(bigIntCircuitHash);


    // console.log(hash);
    // console.log(hash.toString(16));

    // sign in js & verify in circuit

    // console.log(signature);


}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
