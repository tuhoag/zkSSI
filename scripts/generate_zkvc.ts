import fs from "fs";
import { mulPointEscalar, r } from "@zk-kit/baby-jubjub";
import { randomBytes } from "crypto";
import { ethers, ignition } from "hardhat";
import { ChildNodes, Node } from "@zk-kit/smt"
import sha256 from "crypto-js/sha256"
import { poseidon1, poseidon2, poseidon3, poseidon4, poseidon5, poseidon6 } from "poseidon-lite"
import { toBigInt } from "ethers";
import { assert, expect } from "chai";
import { poseidonEncrypt, poseidonDecrypt, poseidonDecryptWithoutCheck } from "@zk-kit/poseidon-cipher"
// import schnorr from "@noir-lang/barretenberg/crypto/schnorr";
import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { Schnorr } from '@noir-lang/barretenberg/dest/crypto/schnorr';
import {
    Signature,
    derivePublicKey,
    signMessage,
    verifySignature,
    deriveSecretScalar,
    packPublicKey,
    unpackPublicKey
} from "@zk-kit/eddsa-poseidon"
import path, { resolve } from "path";
import {
    bigNumberishToBigint,
    bigNumberishToBuffer,
    bufferToBigint,
    isBigNumberish,
    isStringifiedBigint
} from "@zk-kit/utils"
import { newMemEmptyTrie, SMT, SMTMemDb, BigNumberish } from 'circomlibjs';

import lodash from "lodash";
import ZKVCModule from "../ignition/modules/zkvc";

import { MyProofData, NoirProgram, NoirProgramOptions, PerformanceStat, getDefaultNoirProgramOptions } from "./utils";
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import exp from "constants";
import { createSMT as createSparseMerkleTree } from "./circom_smt_utils";
import { hexToBigInt } from "viem";
import math, { combinations } from "mathjs";

function convertNormalStringToBigInt(data: string) {
    const encoder = new TextEncoder();
    const view = encoder.encode(data);
    // console.log(view);

    return bufferToBigint(Buffer.from(view));
}


interface NoirSerializable {
    serializeNoir(): any;
}

// const MAX_CONDITIONS = 3;
// const MAX_ISSUERS = 1;
// const MAX_CREDENTIALS = 1;
// const MAX_CLAIMS = 1;

// const MAX_SIBLINGS = 128;
let MAX_SIBLINGS = 32;

function paddingArray(array: Array<string>, num: number, value: any) {
    while (array.length < num) {
        array.push(value);
    }
}

class MerkleTreeProof implements NoirSerializable {
    // root: bigint;
    siblings: bigint[];
    oldItem: bigint;
    isOld0: number;
    item: bigint;

    constructor(siblings: bigint[], oldItem: bigint, isOld0: number, item: bigint) {
        // this.root = root;
        this.siblings = siblings;
        this.oldItem = oldItem;
        this.isOld0 = isOld0;
        this.item = item;
    }

    static async generateExclusionProof(tree: SMT, item: bigint) {
        const key = tree.F.e(item);
        const res = await tree.find(key);

        let siblings = res.siblings;

        for (let i = 0; i < siblings.length; i++) {
            siblings[i] = tree.F.toObject(siblings[i]);
        }

        assert(siblings.length <= MAX_SIBLINGS, `Siblings has more than ${MAX_SIBLINGS} items.`);


        // const root = tree.F.toObject(tree.root);
        const oldItem = res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey);

        return new MerkleTreeProof(siblings, oldItem, res.isOld0, item);
    }

    serializeNoir() {
        let allSiblings = Array<string>();

        for (let i = 0; i < this.siblings.length; i++) {
            allSiblings[i] = bigIntToHex(this.siblings[i]);
        }

        paddingArray(allSiblings, MAX_SIBLINGS, bigIntToHex(BigInt(0)));
        // while (allSiblings.length < MAX_INPUT_SIBLINGS) {
        //     allSiblings.push(bigIntToHex(BigInt(0)));
        // }

        return {
            // root: bigIntToHex(this.root),
            siblings: allSiblings,
            old_item: bigIntToHex(this.oldItem),
            is_old_0: this.isOld0 ? 1 : 0,
        };
    }
}

class Point implements NoirSerializable {
    x: bigint;
    y: bigint;

    constructor(x: bigint, y: bigint) {
        this.x = x;
        this.y = y;
    }

    serializeNoir() {
        return {
            x: bigIntToHex(this.x),
            y: bigIntToHex(this.y),
        }
    }
}

class Issuer implements NoirSerializable {
    name: string;
    privateKey: string;
    publicKey: Point;

    constructor(name: string, privateKey: string) {
        this.name = name;
        this.privateKey = privateKey;

        const publicKey = derivePublicKey(privateKey);
        this.publicKey = new Point(BigInt(publicKey[0]), BigInt(publicKey[1]));
    }

    serializeNoir() {
        return {
            // name: this.name,
            issuer_code: bigIntToHex(convertNormalStringToBigInt(this.name)),
            public_key: this.publicKey.serializeNoir(),
        }
    }
}

class Claim implements NoirSerializable {
    name: string;
    value: number;

    constructor(name: string, value: number) {
        this.name = name;
        this.value = value;
    }

    serializeNoir() {
        return {
            // name: this.name,
            code: this.getCode(),
            // value: bigIntToHex(BigInt(this.value)),
            value: this.value,
        };
    }

    getCode() {
        return bigIntToHex(convertNormalStringToBigInt(this.name));
    }

}

class MySignature implements NoirSerializable {
    s: bigint;
    r8: Point;

    constructor(rawSignature: Signature<string>) {
        this.s = BigInt(rawSignature.S);
        this.r8 = new Point(
            BigInt(rawSignature.R8[0]),
            BigInt(rawSignature.R8[1])
        );
    }

    serializeNoir() {
        // const temps = bigIntToHex(this.s);
        // console.log(temps, this.s);
        // throw new Error("");

        return {
            s: bigIntToHex(this.s),
            r8: {
                x: bigIntToHex(this.r8.x),
                y: bigIntToHex(this.r8.y),
            }
        };
    }
}

class Credential implements NoirSerializable {
    issuer: Issuer;
    subject: string;
    // subject_code?: bigint;
    claims: Claim[];
    expiredDate: number;
    hash?: bigint;
    hashExpired: boolean;
    signature?: MySignature;
    signatureExpired: boolean;
    nonRevocationProof?: MerkleTreeProof;

    constructor(issuer: Issuer, subject: string, expiredDate: number, claims: Claim[], privateKey: string, nonRevocationProof?: MerkleTreeProof) {
        this.issuer = issuer;
        this.subject = subject;
        // this.subject_code = convertNormalStringToBigInt(subject);
        this.expiredDate = expiredDate;
        this.claims = claims;
        // this.hash = this.hashCredential();
        // this.signature = this.signCredential(privateKey);
        this.hashExpired = true;
        this.signatureExpired = true;
        this.nonRevocationProof = nonRevocationProof;
    }

    serializeNoir() {
        let serializedClaims = Array();
        for (const claim of this.claims) {
            serializedClaims.push(claim.serializeNoir());
        }

        return {
            issuer: this.issuer.serializeNoir(),
            // subject: this.subject,
            subject_code: bigIntToHex(convertNormalStringToBigInt(this.subject)),
            claims: serializedClaims,
            // expired_date: bigIntToHex(BigInt(this.expiredDate)),
            expired_date: this.expiredDate,
            hash: bigIntToHex(this.updateHash()),
            signature: this.updateSignature().serializeNoir(),
            non_revocation_proof: this.nonRevocationProof!.serializeNoir(),
        }
    }

    public updateHash(): bigint {
        if (this.hashExpired) {
            let claimHash;
            // const serializedCredential = this.serializeNoir();

            for (let i = 0; i < this.claims.length; i++) {
                const serializedClaim = this.claims[i];

                if (i == 0) {
                    claimHash = poseidon2([serializedClaim.getCode(), serializedClaim.value]);
                } else {
                    claimHash = poseidon3([claimHash!, serializedClaim.getCode(), serializedClaim.value])
                }
            }

            const credentialHash = poseidon6([
                bigIntToHex(convertNormalStringToBigInt(this.subject)),
                bigIntToHex(convertNormalStringToBigInt(this.issuer.name)), this.issuer.publicKey.x,
                this.issuer.publicKey.y,
                this.expiredDate,
                claimHash!
            ]);

            this.hash = credentialHash;
            this.hashExpired = false;
        }

        return this.hash!;
    }

    public updateSignature(): MySignature {
        if (this.signatureExpired) {
            this.signature = new MySignature(signMessage(this.issuer.privateKey, this.updateHash()));
            this.signatureExpired = false;
        }

        return this.signature!;
    }
}

class UnifiedCredential implements NoirSerializable {
    credentials: Array<Credential>;

    constructor(credentials?: Credential[]) {
        if (credentials === undefined) {
            this.credentials = new Array<Credential>();
        } else {
            this.credentials = credentials;
        }
    }

    public add(credential: Credential) {
        this.credentials.push(credential);
    }

    serializeNoir() {
        let serializedCredentials = new Array();
        let issuers = new Array();
        let issuerMap = new Map<string, number>();

        for (const credential of this.credentials) {
            const { issuer, subject_code, claims, expired_date, hash, signature, non_revocation_proof } = credential.serializeNoir();

            let issuerIndex = issuerMap.get(issuer.issuer_code);

            if (issuerIndex === undefined) {
                issuerIndex = issuers.length
                issuerMap.set(issuer.issuer_code, issuerIndex);
                issuers.push(issuer);
            }

            serializedCredentials.push({
                subject_code, claims, expired_date, signature, non_revocation_proof, issuer_index: issuerIndex
            });
        }

        // issuers (name, public_key)
        // credentials

        return {
            credentials: serializedCredentials,
            issuers
        }
    }
}

class Condition implements NoirSerializable {
    attrName: string;
    operator: string;
    value: bigint;
    issuers: string[];
    operatorMap: Record<string, ComparisonOperator> = {
        "==": ComparisonOperator.Equal,
        "!=": ComparisonOperator.NotEqual,
        ">": ComparisonOperator.GreaterThan,
        "<": ComparisonOperator.LessThan,
        ">=": ComparisonOperator.GreaterThanOrEqual,
        "<=": ComparisonOperator.LessThanOrEqual
    }

    constructor(attrName: string, operator: string, value: number, issuers: string[]) {
        this.attrName = attrName;
        this.operator = operator;
        this.value = BigInt(value);
        this.issuers = issuers;
    }

    hash(): bigint {
        let issuersHash: bigint;

        for (let i = 0; i < this.issuers.length; i++) {
            const currentHash = convertNormalStringToBigInt(this.issuers[i]);

            if (i == 0) {
                issuersHash = currentHash;
            } else {
                issuersHash = poseidon2([issuersHash!, currentHash]);
            }
        }

        return poseidon4([convertNormalStringToBigInt(this.attrName), convertNormalStringToBigInt(this.operator), this.value, issuersHash!]);
    }

    serializeNoir() {
        let issuerCodes = Array<string>();

        for (const issuer of this.issuers) {
            issuerCodes.push(bigIntToHex(convertNormalStringToBigInt(issuer)));
        }

        // let serializedOperator: number;



        return {
            // name: this.name,
            attr_code: bigIntToHex(convertNormalStringToBigInt(this.attrName)),
            operator: this.operatorMap[this.operator],
            // value: bigIntToHex(this.value),
            value: this.value,
            issuer_codes: issuerCodes,
        };
    }
}

type ConditionNode = {
    value: Condition | string;
    left?: ConditionNode;
    right?: ConditionNode;

    // constructor(value: Condition | string, left?: ConditionNode, right?: ConditionNode) {
    //     this.value = value;
    //     this.left = left;
    //     this.right = right;
    // }
}


// const conditions = new ConditionNode(
//     "&",
//     new ConditionNode(
//         "|",
//         new ConditionNode(
//             new Condition("birth_day", "+ ", 10, "issuer00")
//         ),
//         new ConditionNode(
//             new Condition("birth_day", "+ ", 10, "issuer00")
//         )
//     ),
//     new ConditionNode(new Condition("birth_day", "+ ", 10, "issuer00")),
// )

class Criteria implements NoirSerializable {
    root: ConditionNode;

    constructor(root: ConditionNode) {
        this.root = root;
    }

    serializeNoir() {
        let serializedConditions: any[] = [];
        let serializedPredicates: any[] = [];

        let currentNodes = [this.root];
        let addedNodesHash = new Map<bigint, number>();

        while (currentNodes.length > 0) {
            const currentNode = currentNodes.shift();

            // console.log(currentNode);
            // console.log(typeof currentNode!.value === "string");
            if (typeof currentNode!.value === "string") {
                let value = -1;

                if (currentNode?.value == "&") {
                    value = 0;
                } else if (currentNode?.value == "|") {
                    value = 1;
                } else {
                    throw new Error(`Operator ${currentNode?.value} is unsupported`);
                }

                // serializedPredicates.push(bigIntToHex(BigInt(value)));
                serializedPredicates.push(value);

                currentNodes.push(currentNode!.left!);
                currentNodes.push(currentNode!.right!);
            } else {
                // console.log(currentNode);
                const hash = currentNode!.value.hash();

                let addedConditionId = addedNodesHash.get(hash);

                if (addedConditionId === undefined) {
                    addedConditionId = serializedConditions.length;

                    serializedConditions.push((currentNode!.value as Condition).serializeNoir());

                    addedNodesHash.set(hash, addedConditionId);
                }

                // serializedPredicates.push(bigIntToHex(BigInt(addedConditionId + 2)));
                serializedPredicates.push(addedConditionId + 2);
            }
        }

        return {
            conditions: serializedConditions,
            predicates: serializedPredicates,
        };
    }
}

async function generateEmptyNonRevocationTrees(numIssuers: number): Promise<Map<string, SMT>> {
    let issuerRevocationTrees = new Map<string, SMT>();

    for (let i = 0; i < numIssuers; i++) {
        issuerRevocationTrees.set(`issuer0${i}`, await createSparseMerkleTree());
    }

    return issuerRevocationTrees;
}

async function generateRoots(credentials: Credential[], issuerRevocationTrees: Map<string, SMT>) {
    let roots = [];
    for (let credential of credentials) {
        const nonRevocationTree = issuerRevocationTrees.get(credential.issuer.name)!;

        const hash = credential.updateHash();

        const proof = await MerkleTreeProof.generateExclusionProof(nonRevocationTree, hash);
        credential.nonRevocationProof = proof;
        const root = nonRevocationTree.F.toObject(nonRevocationTree.root);
        roots.push(bigIntToHex(root));
    }

    return roots;
}

function generateVCs(numCredentials: number) {
    const privateKey = "secret";
    let credentials: Credential[] = [];

    for (let i = 0; i < numCredentials; i++) {
        credentials.push(new Credential(
            new Issuer(`issuer0${i}`, privateKey),
            "ken",
            5,
            [
                new Claim("birth_day", 19)
            ],
            privateKey)
        );
    }

    return credentials;
}

function getConditionsAndVCs(numConditions: number) {
    let conditions: ConditionNode;
    let credentials: Credential[] = generateVCs(numConditions);

    const conditionsMap2: Record<number, ConditionNode> = {
        1: {
            value: new Condition("birth_day", ">", 10, ["issuer00"])
        },
        2: {
            value: "&",
            left: {
                value: new Condition("birth_day", ">", 10, ["issuer00"]),
            },
            right: {
                value: new Condition("birth_day", ">", 10, ["issuer01"]),
            }
        },
        3: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer00"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer01"]),
                }
            },
            right: {
                value: new Condition("birth_day", ">", 10, ["issuer02"]),
            }
        },
        4: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer00"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer01"]),
                }
            },
            right: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer02"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer03"]),
                }
            }
        },
        5: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer00"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer01"])
                    }
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer02"]),
                }
            },
            right: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer03"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer04"]),
                }
            }
        }
    }

    if (numConditions in conditionsMap2) {
        conditions = conditionsMap2[numConditions];
        // console.log(conditions);
    } else {
        throw new Error(`Unsupported test setting number of conditions: ${numConditions}`);
    }

    return { conditions, credentials };
}

async function generateTestInputs(numIssuers: number) {
    const { conditions, credentials } = getConditionsAndVCs(numIssuers);

    let issuerRevocationTrees = await generateEmptyNonRevocationTrees(numIssuers);
    let roots = await generateRoots(credentials, issuerRevocationTrees);

    const unifiedCredential = new UnifiedCredential(credentials);
    const criteria = new Criteria(
        conditions
    );

    const { credentials: serializedCredentials, issuers } = unifiedCredential.serializeNoir();

    return {
        criteria: criteria.serializeNoir(),
        credentials: serializedCredentials,
        public_keys: issuers,
        proving_time: 0,
        revocation_roots: roots,
    }
}

async function executeSingleProofMultiConditions(inputs: any): Promise<PerformanceStat[]> {
    let performanceStats: PerformanceStat[] = [];

    const options = getDefaultNoirProgramOptions();

    const program = await NoirProgram.createProgram("vcp_generation", options);

    // console.dir(inputs, {depth: null});
    // throw new Error("");

    console.time("prove");
    const proof = await program.prove(inputs, undefined, performanceStats);
    console.timeEnd("prove");
    // console.dir(proof, {depth: null});
    // console.log(bigIntToHex(proof.proof));

    console.time("verify");
    const verification = await program.verify(proof, undefined, performanceStats);
    console.timeEnd("verify");
    console.dir(`off-chain verification: ${verification}`, { depth: null });

    return performanceStats
}

function aggregatePerformanceStats(stats: PerformanceStat[]): PerformanceStat {
    let totalExecutionTime = 0;
    let maxPeakMemoryUsage = -1;
    let meanMeanMemoryUsage = 0;
    let meanStdMemoryUsage = 0;

    for (const stat of stats) {
        totalExecutionTime += stat.executionTime;
        maxPeakMemoryUsage = Math.max(maxPeakMemoryUsage, stat.peakMemoryUsage);
        meanMeanMemoryUsage += stat.meanMemoryUsage;
        meanStdMemoryUsage += stat.stdMemoryUsage;
    }

    return {
        name: stats[0].name,
        executionTime: totalExecutionTime,
        peakMemoryUsage: maxPeakMemoryUsage,
        meanMemoryUsage: meanMeanMemoryUsage / stats.length,
        stdMemoryUsage: meanStdMemoryUsage / stats.length,
    }
}

async function generateProofsForMultiConditions(inputs: any, stats?: PerformanceStat[]): Promise<MyProofData[]> {
    let performanceStats = Array<PerformanceStat>();
    let proofs = Array<MyProofData>();
    const options = getDefaultNoirProgramOptions();
    const program = await NoirProgram.createProgram("mono_vcp_generation", options);

    for(const condition of inputs.criteria.conditions) {
        for(let iVC = 0; iVC < inputs.credentials.length; iVC ++) {
            const vc = inputs.credentials[iVC];

            const issuerCode = inputs.public_keys[vc.issuer_index].issuer_code;

            if (condition.issuer_codes.includes(issuerCode)) {
                const subInput = {
                    criteria: {
                        conditions: [condition],
                        predicates: [2]
                    },
                    credentials: [
                        {
                            ...vc,
                            issuer_index: 0
                        }
                    ],
                    public_keys: [
                        inputs.public_keys[vc.issuer_index]
                    ],
                    revocation_roots: [
                        inputs.revocation_roots[iVC]
                    ],
                    proving_time: inputs.proving_time,
                }
                const proof = await program.prove(subInput, undefined, performanceStats);
                proofs.push(proof);
            }
        }
    }

    let aggStat = aggregatePerformanceStats(performanceStats);
    aggStat.name = "proveMulti";
    stats!.push(aggStat);

    return proofs;
}

async function verifyProofsForMultiConditions(inputs: any, proofs: MyProofData[], stats?: PerformanceStat[]): Promise<boolean> {
    const predicates = inputs.criteria.predicates;
    const options = getDefaultNoirProgramOptions();
    const program = await NoirProgram.createProgram("mono_vcp_generation", options);

    let validations = Array<boolean>();
    let performanceStats = Array<PerformanceStat>();

    for(let i = predicates.length - 1; i >= 0; i--) {
        const left = i * 2 + 1;
        const right = i * 2 + 1;
        const inverseLeft = predicates.length - left - 1;
        const inverseRight = predicates.length - right - 1;
        // console.log(`i: ${i} - left=${left} - right=${right} - inverseLeft=${inverseLeft} - inverseRight=${inverseRight}`);

        if (predicates[i] == 0) {
            validations[i] = validations[inverseLeft] && validations[inverseRight];
        } else if (predicates[i] == 1) {
            validations[i] = validations[inverseLeft] || validations[inverseRight];
        } else if (predicates[i] >= 2) {
            // verify
            const proof = proofs[predicates[i] - 2];
            const verification = await program.verify(proof, undefined, performanceStats);
            validations.push(verification);
        } else {
            throw new Error(`Predicate ${predicates[i]} is invalid`);
        }

        // console.log(predicates[i]);
    }

    let aggStat = aggregatePerformanceStats(performanceStats);
    aggStat.name = "verifyMulti";
    stats!.push(aggStat);

    // console.log(validations[0]);
    // throw new Error("");

    return validations[0];
}

async function executeMultiProofMultiConditions(inputs: any): Promise<PerformanceStat[]> {
    let performanceStats: PerformanceStat[] = [];

    // generate proofs for each condition
    console.time("prove");
    const proofs = await generateProofsForMultiConditions(inputs, performanceStats);
    console.timeEnd("prove");

    // verify proofs according to predicates
    console.time("verify");
    const verification = await verifyProofsForMultiConditions(inputs, proofs, performanceStats);
    console.timeEnd("verify");

    console.dir(`off-chain verification: ${verification}`, { depth: null });

    return performanceStats
}

async function writeExpData(expData: any[], name: string) {
    const expDataPath = resolve(__dirname, "..", "reports", `${name}.json`);
    fs.writeFileSync(expDataPath, JSON.stringify(expData));
    console.log(`wrote exp data to ${expDataPath}`);
}


enum zkVCMode {
    SingleProof = 0,
    MultiProof,
}

enum ComparisonOperator {
    Equal = 0,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

async function evaluate(mode: zkVCMode) {
    let expData = [];

    const treeHeight = 32;
    const numConditions = 2;
    const numTrials = 1;

    for (let trial = 0; trial < numTrials; trial++) {
        MAX_SIBLINGS = treeHeight;

        console.log(`Setting: treeHeight=${treeHeight} - numConditions=${numConditions} - trial=${trial}`);
        const inputs = await generateTestInputs(numConditions);

        let currentStats:PerformanceStat[];

        if (mode == zkVCMode.SingleProof) {
            currentStats = await executeSingleProofMultiConditions(inputs);
        } else if (mode == zkVCMode.MultiProof) {
            currentStats = await executeMultiProofMultiConditions(inputs);
        } else {
            throw new Error(`Unsupported execution mode: ${mode}`);

        }

        for (const stat of currentStats) {
            expData.push({
                ...stat,
                trial: trial,
                treeHeight: treeHeight,
                numConditions: numConditions,
            });
        }
    }

    console.dir(expData, { depth: null });

    await writeExpData(expData, `offchain-${treeHeight}-${numConditions}-${mode}`);
}

async function main() {
    evaluate(zkVCMode.SingleProof);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
