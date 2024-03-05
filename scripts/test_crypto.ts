import toml from '@iarna/toml';
import util from "util";
import fs from "fs";
import { NoirProgram, NoirProgramOptions } from "./utils";
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
import { publicDecrypt, sign } from "crypto";
import { ChildNodes, SMT, MerkleProof, Entry, Node, Siblings } from "@zk-kit/smt";
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import { match } from "assert";
import { assert } from "console";

const TREE_DEPTH = 10;

function convertIntToHexString(data: number | string | bigint) {
    return `0x${BigInt(data).toString(16)}`;
}

function createSparseMerkleTree() {
    const hashFn = (childNodes: ChildNodes) => {
        let hashed_value: any;

        if (childNodes.length % 2 == 0) {
            hashed_value = poseidon2(childNodes)
        } else {
            hashed_value = poseidon3(childNodes);
        }

        return hashed_value;
    };

    return new SMT(hashFn, true);
}

class MyOption<T> {
    value?: T;

    constructor(value?: T) {
        this.value = value;
    }

    isSome() {
        return this.value !== undefined;
    }

    isNone() {
        return this.value === undefined;
    }

    serializeNoir() {
        if (this.isSome()) {
            return {
                "_is_some": bigIntToHex(BigInt(Number(this.isSome()))),
                "_value": bigIntToHex(this.value! as bigint),
            }
        } else {
            return {
                "_is_some": bigIntToHex(BigInt(Number(this.isSome()))),
                "_value": bigIntToHex(BigInt(0))
            }
        }

    }
}

function some<T>(value: T) {
    return new MyOption<T>(value);
}

function none<T>() {
    return new MyOption<T>();
}

type NoirProofData = {
    publicInputs: Map<string,string>;
    proof: Uint8Array;
}

class MyMerkleProof {
    // in this project, we only care about the key (i.e., key is always equal to value). Thus, we only need to store a value
    entry: bigint;
    matchingEntry: MyOption<bigint>[];
    siblings: bigint[];
    root: bigint;
    membership: boolean;

    constructor(merkleProof: MerkleProof) {
        // console.log("construct my merkle proof");
        // console.log(merkleProof);
        this.entry = BigInt(merkleProof.entry[0]);

        if (merkleProof.matchingEntry === undefined) {
            this.matchingEntry = [
                none(), none()
            ];
        } else {
            this.matchingEntry = [
                some(BigInt(merkleProof.matchingEntry[0]!)),
                some(BigInt(merkleProof.matchingEntry[1]!))
            ];
        }

        this.siblings = Array<bigint>();
        for (const sibling of merkleProof.siblings) {
            // console.log(`sibling: ${sibling} - converted: ${BigInt(sibling)}`);
            // console.log(BigInt(sibling));
            this.siblings.push(BigInt(sibling));
        }

        // console.log('siblings');
        // console.log(this.siblings);
        // console.log(merkleProof.siblings);


        this.root = BigInt(merkleProof.root);
        this.membership = merkleProof.membership;
    }

    serializeNoir() {
        let siblings = new Array<string>();
        // for (let i = 0; i < this.siblings.length; i++) {
        //     siblings.push(bigIntToHex(BigInt(this.siblings[i])));
        // }

        // for (let i = this.siblings.length; i < TREE_DEPTH; i++) {
        //     siblings.push(bigIntToHex(BigInt(0)));
        // }
        for (let i = 0; i < TREE_DEPTH; i++) {
            if (i < TREE_DEPTH - this.siblings.length) {
                siblings.push(bigIntToHex(BigInt(0)));
            } else {
                const sibling = this.siblings[TREE_DEPTH - i - 1];
                siblings.push(bigIntToHex(BigInt(sibling.valueOf())));
            }
        }

        let matchingEntry = [
            this.matchingEntry[0].serializeNoir(),
            this.matchingEntry[1].serializeNoir(),
        ];

        // if (this.matchingEntry.isNone()) {
        //     matchingEntry = [
        //         none(),
        //         none(),
        //     ]
        // } else {
        //     matchingEntry = [
        //         some<string>(bigIntToHex(BigInt(this.matchingEntry[0].value))),
        //         some<string>(bigIntToHex(BigInt(this.matchingEntry[1].))),
        //     ]
        // }

        return {
            siblings: siblings,
            matching_entry: matchingEntry,
            root: bigIntToHex(this.root)
        }
    }
}

async function generateMerkleTreeProofSMT254() {
    const privateKey = "secret";
    const publicKey = derivePublicKey(privateKey);

    const values = [
        [1, 2],
        [2, 3],
        [3, 4],
    ];

    let revocationTree = createSparseMerkleTree();

    let hashes = new Array();
    let signatures = new Array();

    for (const value of values) {
        const hash = poseidon2(value);
        const signature = signMessage(privateKey, hash);

        hashes.push(hash);
        signatures.push(signature);
    }

    revocationTree.add(hashes[0], hashes[0]);

    console.log(bigIntToHex(BigInt(revocationTree.root)));

    revocationTree.add(hashes[1], hashes[1]);

    console.log(bigIntToHex(BigInt(revocationTree.root)));

    // const firstProof = new MyMerkleProof(revocationTree.createProof(hashes[0]));
    // console.log(firstProof.serializeNoir());

    // revocationTree.add(hashes[1], hashes[1]);

    const proofs = new Array<MyMerkleProof>();
    for (const hash of hashes) {
        const proof = revocationTree.createProof(hash);
        console.dir(proof);
        const verification = revocationTree.verifyProof(proof);
        console.log(verification);
        const newProof = new MyMerkleProof(proof);
        console.log(newProof.serializeNoir());

        proofs.push(new MyMerkleProof(revocationTree.createProof(hash)));
    }
    // return;
    console.dir(`hashes: ${hashes}`, {depth: 3});
    // console.log(util.inspect(proofs));
    console.dir(proofs, {depth:3});
    const index = 2;

    const old_serializable = proofs[index].serializeNoir();
    let inputs = {
        // message: [convertIntToHexString(values[index][0]), convertIntToHexString(values[index][1])],
        // public_key: {
        //     x: convertIntToHexString(publicKey[0]),
        //     y: convertIntToHexString(publicKey[1]),
        // },
        hash: convertIntToHexString(hashes[index]),
        // signature: {
        //     s: convertIntToHexString(signatures[index]["S"]),
        //     r8_x: convertIntToHexString(signatures[index]["R8"][0]),
        //     r8_y: convertIntToHexString(signatures[index]["R8"][1]),
        // },
        // proof: {
        //     root: old_serializable.root,
        //     siblings: old_serializable.siblings
        // },
        proof: proofs[index].serializeNoir()

        // temp: some<1>(1).serializeNoir(),
    }
    console.dir(inputs, { depth: 3 });

    // const str = toml.stringify(inputs);
    // fs.writeFileSync("inputs.json", JSON.stringify(inputs));
    // fs.writeFileSync("inputs.toml", toml.stringify(inputs));
    const options: NoirProgramOptions = {
        threads: 8,
        compiled: false,
        isJSProving: false,
        proverName: "Prover",
        verifierName: "Verifier",
    }
    const program = await NoirProgram.createProgram("test_smt_bn254", options);
    // const program = await NoirProgram.createProgram("test_smtverifier_noir", { threads: 8, compiled: true, isJSProving: false });
    // const proof = await program.prove(inputs);
    const proof = await program.prove(inputs, options);

    console.log(proof);

    // message: pub [Field; 2],
    // public_key: pub PublicKey,
    // hash: pub Field,
    // signature: pub Signature,
    // proof: MerkleTreeProof,
    // root: Field
}

async function generateMerkleTreeProofSMTVerifier() {
    const privateKey = "secret";
    const publicKey = derivePublicKey(privateKey);

    const values = [
        [1, 2],
        [2, 3],
        [3, 4],
    ];

    let revocationTree = createSparseMerkleTree();

    let hashes = new Array();
    let signatures = new Array();

    for (const value of values) {
        const hash = poseidon2(value);
        const signature = signMessage(privateKey, hash);

        hashes.push(hash);
        signatures.push(signature);
    }

    revocationTree.add(hashes[0], hashes[0]);

    console.log(bigIntToHex(BigInt(revocationTree.root)));

    revocationTree.add(hashes[1], hashes[1]);

    console.log(bigIntToHex(BigInt(revocationTree.root)));

    // const firstProof = new MyMerkleProof(revocationTree.createProof(hashes[0]));
    // console.log(firstProof.serializeNoir());

    // revocationTree.add(hashes[1], hashes[1]);

    const proofs = new Array<MyMerkleProof>();
    for (const hash of hashes) {
        const proof = revocationTree.createProof(hash);
        console.dir(proof);
        const verification = revocationTree.verifyProof(proof);
        console.log(verification);
        const newProof = new MyMerkleProof(proof);
        console.log(newProof.serializeNoir());

        proofs.push(new MyMerkleProof(revocationTree.createProof(hash)));
    }
    // return;
    console.dir(`hashes: ${hashes}`, {depth: 3});
    // console.log(util.inspect(proofs));
    console.dir(proofs, {depth:3});
    const index = 2;

    const old_serializable = proofs[index].serializeNoir();
    let inputs = {
        // message: [convertIntToHexString(values[index][0]), convertIntToHexString(values[index][1])],
        // public_key: {
        //     x: convertIntToHexString(publicKey[0]),
        //     y: convertIntToHexString(publicKey[1]),
        // },
        hash: convertIntToHexString(hashes[index]),
        // signature: {
        //     s: convertIntToHexString(signatures[index]["S"]),
        //     r8_x: convertIntToHexString(signatures[index]["R8"][0]),
        //     r8_y: convertIntToHexString(signatures[index]["R8"][1]),
        // },
        // proof: {
        //     root: old_serializable.root,
        //     siblings: old_serializable.siblings
        // },
        proof: proofs[index].serializeNoir()

        // temp: some<1>(1).serializeNoir(),
    }
    console.dir(inputs, { depth: 3 });

    // const str = toml.stringify(inputs);
    // fs.writeFileSync("inputs.json", JSON.stringify(inputs));
    // fs.writeFileSync("inputs.toml", toml.stringify(inputs));
    const options: NoirProgramOptions = {
        threads: 8,
        compiled: false,
        isJSProving: false,
        proverName: "Prover",
        verifierName: "Verifier",
    }
    const program = await NoirProgram.createProgram("test_smt_bn254", options);
    // const program = await NoirProgram.createProgram("test_smtverifier_noir", { threads: 8, compiled: true, isJSProving: false });
    // const proof = await program.prove(inputs);
    const proof = await program.prove(inputs, options);

    console.log(proof);

    // message: pub [Field; 2],
    // public_key: pub PublicKey,
    // hash: pub Field,
    // signature: pub Signature,
    // proof: MerkleTreeProof,
    // root: Field
}

async function main() {
    // const privateKey = "secret";
    // const publicKey = derivePublicKey(privateKey);
    // // console.log(`public key: ${publicKey}`);

    // const hash1 = poseidon2([1, 2]);
    // const hash2 = poseidon2([2, 3]);
    // console.log(hash);
    // const signature = signMessage(privateKey, hash);
    // console.log(signature);

    // generate merkle tree proof
    await generateMerkleTreeProofSMT254();

    // let hexInputs = {
    //     message: [convertIntToHexString(message[0]), convertIntToHexString(message[1])],
    //     public_key: {
    //         x: convertIntToHexString(publicKey[0]),
    //         y: convertIntToHexString(publicKey[1]),
    //     },
    //     hash: convertIntToHexString(hash),
    //     signature: {
    //         s: convertIntToHexString(signature["S"]),
    //         r8_x: convertIntToHexString(signature["R8"][0]),
    //         r8_y: convertIntToHexString(signature["R8"][1]),
    //     }
    // }

    // console.log(hexInputs);

    // const program = await NoirProgram.createProgram("test", { threads: 8 });
    // const proof = await program.prove(hexInputs);
    // console.log(proof);
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
