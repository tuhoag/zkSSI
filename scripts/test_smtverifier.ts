
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
// import { ChildNodes, SMT, MerkleProof, Entry, Node, Siblings } from "@zk-kit/smt";
import { bigIntToHex, bytesToHex, bytesToBigInt } from "@nomicfoundation/ethereumjs-util";
import { match } from "assert";
import { assert } from "console";
import { newMemEmptyTrie, SMT, SMTMemDb, BigNumberish  } from 'circomlibjs';
import { checkHex } from '@zk-kit/smt';
import { createSMT, getMyHashes } from './circom_smt_utils';

const TREE_DEPTH = 10;


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

interface NoirSerializable {
    serializeNoir(): any;
}

const MAX_INPUT_SIBLINGS = 10;

class MerkleTreeProof implements NoirSerializable {
    root: bigint;
    siblings: bigint[];
    oldItem: bigint;
    isOld0: number;
    item: bigint;

    constructor(root: bigint, siblings: bigint[], oldItem: bigint, isOld0: number, item: bigint) {
        this.root = root;
        this.siblings = siblings;
        this.oldItem = oldItem;
        this.isOld0 = isOld0;
        this.item = item;
    }

    static async generateExclusionProof(tree: SMT, item: bigint) {
        const key = tree.F.e(item);
        const res = await tree.find(key);

        let siblings = res.siblings;

        for (let i=0; i<siblings.length; i++) {
            siblings[i] = tree.F.toObject(siblings[i]);
        }

        assert(siblings.length <= MAX_INPUT_SIBLINGS, `Siblings has more than ${MAX_INPUT_SIBLINGS} items.`);


        const root = tree.F.toObject(tree.root);
        const oldItem = res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey);

        return new MerkleTreeProof(root, siblings, oldItem, res.isOld0, item);
    }

    serializeNoir() {
        let allSiblings = Array<string>();

        for (let i=0; i<this.siblings.length; i++) {
            allSiblings[i] = bigIntToHex(this.siblings[i]);
        }

        while (allSiblings.length < MAX_INPUT_SIBLINGS) {
            allSiblings.push(bigIntToHex(BigInt(0)));
        }

        return {
            root: bigIntToHex(this.root),
            siblings: allSiblings,
            old_item: bigIntToHex(this.oldItem),
            is_old_0: this.isOld0 ? bigIntToHex(BigInt(1)): bigIntToHex(BigInt(0)),
        };
    }
}

async function checkExclusion(tree: SMT, _key: bigint) {
    const rawInputs = await MerkleTreeProof.generateExclusionProof(tree, _key);

    const inputs = rawInputs.serializeNoir();

    const noirInputs = {
        proof: rawInputs.serializeNoir(),
        key: bigIntToHex(_key),
    };
    // const inputs = {
    //     root: bigIntToHex(tree.F.toObject(tree.root)),
    //     siblings: siblings,
    //     oldKey: res.isOld0 ? 0 : bigIntToHex(tree.F.toObject(res.notFoundKey)),
    //     oldValue: res.isOld0 ? 0 : bigIntToHex(tree.F.toObject(res.notFoundValue)),
    //     isOld0: res.isOld0 ? bigIntToHex(BigInt(1)): bigIntToHex(BigInt(0)),
    //     key: bigIntToHex(_key),
    //     value: bigIntToHex(BigInt(0)),
    // }

    console.log(bigIntToHex(_key));

    const options: NoirProgramOptions = {
        threads: 8,
        compiled: false,
        isJSProving: false,
        proverName: "Prover",
        verifierName: "Verifier",
    }

    console.log(rawInputs);
    console.log(inputs);
    const program = await NoirProgram.createProgram("test_smtverifier_noir", options);
    const proof = await program.prove(noirInputs, options);

    console.log(proof);
}


async function generateMerkleTreeProofSMTVerifier() {
    const privateKey = "secret";
    const publicKey = derivePublicKey(privateKey);

    const values = [
        [1, 2],
        [2, 3],
        [3, 4],
    ];

    let hashes = new Array();
    let signatures = new Array();

    for (const value of values) {
        const hash = poseidon2(value);
        const signature = signMessage(privateKey, hash);

        hashes.push(hash);
        signatures.push(signature);
    }

    let revocationTree = await createSMT();

    await revocationTree.insert(hashes[0], hashes[0]);
    await revocationTree.insert(hashes[1], hashes[1]);

    await checkExclusion(revocationTree, hashes[2]);
}

async function main() {
    // generate merkle tree proof
    await generateMerkleTreeProofSMTVerifier();
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
