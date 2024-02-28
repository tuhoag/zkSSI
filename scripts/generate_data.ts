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
// import { Blake512 } from "blake-hash/lib";
import createBlakeHash from "blake-hash";


async function generateRevokedData(data: any) {
  const hash = (childNodes: ChildNodes) => {
    let hashed_value: any;

    if (childNodes.length % 2 == 0) {
      hashed_value = poseidon2(childNodes)
    } else {
      hashed_value = poseidon3(childNodes);
    }

    return hashed_value;
  };

  const revocationTree = new SMT(hash, true);

  // revoke all claims
  let revokedKeys = new Set<string>();

  for (const revokedItem of data.revocation.revokedClaims) {
    const holder = revokedItem["holder"];
    const index = revokedItem["index"];
    revokedKeys.add(`${holder}:${index}`);

    const claim = data.claims[holder][index];

    const hashedClaim = `0x${claim["hash"]}`;
      // console.log(hashedClaim);
      const intClaim = BigInt(hashedClaim);

      revocationTree.add(intClaim, intClaim);
      const root = revocationTree.root;

      // console.log(root);

      data.revocation.revocationTreeRoots.push(root);
  }

  // console.log(revokedKeys);

  for (const holder_name in data.claims) {
    for (let index = 0; index < data.claims[holder_name].length; index ++) {
      const claim = data.claims[holder_name][index];
      const key = `${holder_name}:${index}`;

      // if (!revokedKeys.has(key)) {
        const hashedClaim = `0x${claim["hash"]}`;
        // console.log(hashedClaim);
        const intClaim = BigInt(hashedClaim);
        const proof = revocationTree.createProof(intClaim);
        claim["nonRevocationProof"] = proof;
        claim["revocationTreeVersion"] = data.revocation.revocationTreeRoots.length - 1;

        // console.log(key);
      // } else {
      //   claim["nonRevocationProof"] = undefined;
      // }
    }
  }
}

async function generateIssuedData(data: any) {
  for (const holder_name in data.claims) {
    for (let claim of data.claims[holder_name]) {
      const issuer = claim["issuer"];
      let privateKey;
      let publicKey;

      if (!("keys" in data.issuers[issuer])) {
        // Your private key (secret).
        privateKey = "secret"

        // Derive a public key from the private key.
        publicKey = derivePublicKey(privateKey)

        data.issuers[issuer]["keys"] = {
          "privateKey": privateKey,
          "publicKey": publicKey
        }
      } else {
        privateKey = data.issuers[issuer]["keys"]["privateKey"];
        publicKey = data.issuers[issuer]["keys"]["publicKey"];
      }

      const signature = signMessage(privateKey, JSON.stringify(claim));
      claim["hash"] = createBlakeHash("blake512").update(JSON.stringify(claim)).digest("hex");

      claim["signature"] = signature;

      // generate expired date
      const issuedDate = new Date();
      const expiredDate = new Date(issuedDate).setFullYear(issuedDate.getFullYear() + 1);

      claim["issuedDate"] = issuedDate.getTime();
      claim["expiredDate"] = expiredDate;


      console.log(claim);
    }
  }
}

async function main() {
  const pathDir = path.resolve(__dirname, "..", "data");

  let data = JSON.parse(fs.readFileSync(path.resolve(pathDir, "claims.json"), "utf-8"));

  generateIssuedData(data);
  generateRevokedData(data);

  fs.writeFileSync(path.resolve(pathDir, "data.json"), JSON.stringify(data, (key, value) => {
    return typeof value === 'bigint'
                ? value.toString()
                : value
  }), "utf-8");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
