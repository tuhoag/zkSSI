import fs from "fs";
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import { Signature, derivePublicKey, signMessage } from "@zk-kit/eddsa-poseidon";
import { bufferToBigint } from "@zk-kit/utils";
import { assert } from "chai";
import { SMT } from "circomlibjs";
import { ethers } from "hardhat";
import { resolve } from "path";
import { poseidon2, poseidon3, poseidon4, poseidon6 } from "poseidon-lite";

export function changeToHex(hexStr: string) {
    if (hexStr == "0x0") {
        return ethers.ZeroHash;
    } else {
        return ethers.zeroPadValue(hexStr, 32);
    }
}

function paddingArray(array: Array<string>, num: number, value: any) {
    while (array.length < num) {
        array.push(value);
    }
  }

function convertNormalStringToBigInt(data: string) {
    const encoder = new TextEncoder();
    const view = encoder.encode(data);

    return bufferToBigint(Buffer.from(view));
}

export type ConditionNode = {
    value: Condition | string;
    left?: ConditionNode;
    right?: ConditionNode;
}

interface NoirSerializable {
    serializeNoir(): any;
}

enum ComparisonOperator {
    Equal = 0,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

export class Condition implements NoirSerializable {
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

export class Claim implements NoirSerializable {
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


export class Credential implements NoirSerializable {
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

export class UnifiedCredential implements NoirSerializable {
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

export class MerkleTreeProof implements NoirSerializable {
    // root: bigint;
    siblings: bigint[];
    oldItem: bigint;
    isOld0: number;
    item: bigint;

    static maxSiblings: number;

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

        assert(siblings.length <= MerkleTreeProof.maxSiblings, `Siblings has more than ${MerkleTreeProof.maxSiblings} items.`);


        // const root = tree.F.toObject(tree.root);
        const oldItem = res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey);

        return new MerkleTreeProof(siblings, oldItem, res.isOld0, item);
    }

    serializeNoir() {
        let allSiblings = Array<string>();

        for (let i = 0; i < this.siblings.length; i++) {
            allSiblings[i] = bigIntToHex(this.siblings[i]);
        }

        paddingArray(allSiblings, MerkleTreeProof.maxSiblings, bigIntToHex(BigInt(0)));
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

export class Point implements NoirSerializable {
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

export class Issuer implements NoirSerializable {
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

export class Criteria implements NoirSerializable {
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


export function prepareDataForMultiConditions(inputs: any) {
    let subInputs = Array();

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

                subInputs.push(subInput);
            }
        }
    }

    // console.dir(subInputs, {depth: null});
    // throw new Error("");

    return subInputs;
}

export async function writeExpData(expData: any[], expName: string, name: string) {
    const expDataPath = resolve(process.cwd(), "reports", "data", expName, `${name}.json`);
    fs.writeFileSync(expDataPath, JSON.stringify(expData, null, 4));
    console.log(`wrote exp data to ${expDataPath}`);
}

export async function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}