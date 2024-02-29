import fs from "fs";
import { mulPointEscalar, r } from "@zk-kit/baby-jubjub";
import { randomBytes } from "crypto";
import { ethers } from "hardhat";
import { ChildNodes, Node, SMT } from "@zk-kit/smt"
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
import path from "path";
import {
    BigNumberish,
    bigNumberishToBigint,
    bigNumberishToBuffer,
    bufferToBigint,
    isBigNumberish,
    isStringifiedBigint
} from "@zk-kit/utils"

import lodash from "lodash";

import { NoirProgram } from "./utils";
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
// import { any } from "hardhat/internal/core/params/argumentTypes";

function convertNormalStringToBigInt(data: string) {
    const encoder = new TextEncoder();
    const view = encoder.encode(data);
    // console.log(view);

    return bufferToBigint(Buffer.from(view));
}

function convertIntToHexString(data: number | string | bigint) {
    return bigIntToHex(BigInt(data));
}

interface NoirSerializable {
    serializeNoir(): any;
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
            name: this.name,
            code: bigIntToHex(convertNormalStringToBigInt(this.name)),
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
            name: this.name,
            code: this.getCode(),
            value: bigIntToHex(BigInt(this.value)),
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
        this.r8 = new Point (
            BigInt(rawSignature.R8[0]),
            BigInt(rawSignature.R8[1])
        );
    }

    serializeNoir() {
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

    constructor(issuer: Issuer, subject: string, expiredDate: number, claims: Claim[], privateKey: string) {
        this.issuer = issuer;
        this.subject = subject;
        // this.subject_code = convertNormalStringToBigInt(subject);
        this.expiredDate = expiredDate;
        this.claims = claims;
        // this.hash = this.hashCredential();
        // this.signature = this.signCredential(privateKey);
        this.hashExpired = true;
        this.signatureExpired = true;
    }

    serializeNoir() {
        let serializedClaims = Array();
        for (const claim of this.claims){
            serializedClaims.push(claim.serializeNoir());
        }

        return {
            issuer: this.issuer.serializeNoir(),
            subject: this.subject,
            subject_code: bigIntToHex(convertNormalStringToBigInt(this.subject)),
            claims: serializedClaims,
            expired_date: bigIntToHex(BigInt(this.expiredDate)),
            hash: bigIntToHex(this.updateHash()),
            signature: this.updateSignature().serializeNoir(),
        }
    }

    public updateHash(): bigint {
        if (this.hashExpired) {
            let claimBigInt;
            // const serializedCredential = this.serializeNoir();

            for (let i = 0; i < this.claims.length; i++) {
                const serializedClaim = this.claims[i];

                if (i == 0) {
                    claimBigInt = poseidon2([serializedClaim.getCode(), serializedClaim.value]);
                } else {
                    claimBigInt = poseidon3([claimBigInt!, serializedClaim.getCode(), serializedClaim.value])
                }
            }

            const credentialHash = poseidon6([
                bigIntToHex(convertNormalStringToBigInt(this.subject)),
                bigIntToHex(convertNormalStringToBigInt(this.issuer.name)), this.issuer.publicKey.x,
                this.issuer.publicKey.y,
                this.expiredDate,
                claimBigInt!
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
        for (const credential of this.credentials) {
            serializedCredentials.push(credential.serializeNoir());
        }

        return {
            credentials: serializedCredentials
        }
    }
}

class Condition implements NoirSerializable {
    name: string;
    operator: string;
    value: bigint;
    issuer: string;

    constructor(name: string, operator: string, value: number, issuer: string) {
        this.name = name;
        this.operator = operator;
        this.value = BigInt(value);
        this.issuer = issuer;
    }

    serializeNoir() {
        return {
            name: this.name,
            operator: this.operator,
            value: bigIntToHex(this.value),
            issuer: this.issuer,
        };
    }
}
class Criteria implements NoirSerializable {
    conditions: Array<Condition>;
    combinations: Array<string>;
    validDate: number;

    constructor(conditions: Condition[], combinations: string[], validDate: number) {
        this.combinations = combinations;
        this.conditions = conditions;
        this.validDate = validDate;
    }

    serializeNoir() {
        let serializedConditions = new Array();
        for (const condition of this.conditions) {
            serializedConditions.push(condition.serializeNoir());
        }

        return {
            conditions: serializedConditions,
            combinations: this.combinations,
            valid_date: bigIntToHex(BigInt(this.validDate)),
        };
    }
}


async function main() {
    const privateKey = "secret";

    const credential = new UnifiedCredential([new Credential(
        new Issuer("issuer00", privateKey),
        "ken     ",
        4,
        [
            new Claim("birth_day ", 19)
        ],
        privateKey
    )]);

    const criteria = new Criteria(
        [
            new Condition("birth_day ", "> ", 18, "issuer00"),
            new Condition("birth_day ", "> ", 18, "issuer00"),
        ],
        [ "&" ],
        5
    );

    const inputs = {
        criteria: criteria.serializeNoir(),
        credential: credential.serializeNoir(),
    }


    const program = await NoirProgram.createProgram("vc_presentation_generation", { threads: 8 });
    const proof = await program.prove(inputs);
    console.log(proof);

    // const verification = await program.verify(proof);
    // console.log(verification);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
