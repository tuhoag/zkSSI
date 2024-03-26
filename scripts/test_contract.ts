import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import { ethers, ignition } from "hardhat";
import zkVCModule from "../ignition/modules/zkvc";
import { generateTestInputs } from "./util/simulation";
import { MyProofData, NARGO, NoirProgram, NoirProgramOptions, getDefaultNoirProgramOptions } from "./util/noir_program";
import { boolean } from "mathjs";
import { prepareDataForMultiConditions } from "./util/data";



function changeToHex(hexStr: string) {
    if (hexStr == "0x0") {
        return ethers.ZeroHash;
    } else {
        return ethers.zeroPadValue(hexStr, 32);
    }
}

async function multiProofVerification(testInput: any) {
    const { singleProofVerifier, multiProofVerifier, vcpGenerationVerifier, monoVcpGenerationVerifier } = await ignition.deploy(zkVCModule);
    const subInputs = prepareDataForMultiConditions(testInput);
    let proofs = Array();

    let options = getDefaultNoirProgramOptions();
    options.runningClient = NARGO;
    const program = await NoirProgram.createProgram("mono_vcp_generation", options);
    let rawProofs = Array();
    for (const subInput of subInputs) {
        const proof = await multiProofComputation(program, options, subInput, false);
        proofs.push(proof.proof);
        rawProofs.push(proof);
        // console.dir(proof, {depth: null});

    }

    const data = modifyInputsForContracts(testInput);

    await multiProofVerifier.updateRequirement(data.requirement, {publicKeys: data.publicKeys}, data.revocationRoots);
    console.dir(`on-chain revocation roots: ${await multiProofVerifier.getRevocationTreeRoots()}`, {depth: null});
    console.log(`on-chain requirement: ${await multiProofVerifier.getRequirement()}`);
    // console.log(proofs);

    for (let i = 0; i < proofs.length; i++) {
        let publicInputs = await multiProofVerifier.preparePublicInputs(0, i);


        // console.dir(rawProofs[i].publicInputs, { depth: null });
        const proof = proofs[i];
        const rawProof = rawProofs[i];
        // console.log(proof);
        const newPublicInputs = [
            rawProof.publicInputs[2].conditions[0].attr_code,
            rawProof.publicInputs[2].conditions[0].operator,
            rawProof.publicInputs[2].conditions[0].value,
            rawProof.publicInputs[2].conditions[0].issuer_codes[0],
            rawProof.publicInputs[2].predicates[0],

            rawProof.publicInputs[3][0].issuer_code,
            rawProof.publicInputs[3][0].public_key.x,
            rawProof.publicInputs[3][0].public_key.y,

            changeToHex(rawProof.publicInputs[0]),

            changeToHex(rawProof.publicInputs[1][0]),
        ]

        console.log(publicInputs);
        console.log(newPublicInputs);
        let verification = await monoVcpGenerationVerifier.verify(proof, newPublicInputs);
        console.log(`on-chain verification ${i}: ${verification}`);

        let verification2 = await multiProofVerifier.verifyCondition(proof, 0, i);
        console.log(`on-chain verification2 ${i}: ${verification2}`);
    }

    multiProofVerifier.on("OnCondition", (i, p, j) => {
        console.log(`OnCondition: ${i}, ${p}, ${j}`);
    })

    multiProofVerifier.on("OnValidation", (i) => {
        console.log(`OnValidation: ${i}`);
    })

    console.log(await multiProofVerifier.getNumPredicates());
    console.log(await multiProofVerifier.verifyConditions(proofs, 0));
    console.log(await multiProofVerifier.verifyPredicates([true, true]));

    const verification = await multiProofVerifier.verify(proofs, 0);
    console.log(`on-chain verification: ${verification}`);
}

async function singleProofVerification(testInput: any) {
    const data = modifyInputsForContracts(testInput);

    const proof = await offChainComputation("vcp_generation", testInput);
    console.dir(proof, {depth: null});

    const { singleProofVerifier, vcpGenerationVerifier } = await ignition.deploy(zkVCModule);

    await singleProofVerifier.updateRequirement(data.requirement, {publicKeys: data.publicKeys}, data.revocationRoots);

    console.dir(`on-chain revocation roots: ${await singleProofVerifier.getRevocationTreeRoots()}`, {depth: null});

    console.log(`on-chain requirement: ${await singleProofVerifier.getRequirement()}`);

    const publicInputs: string[] = [
        proof.publicInputs[2].conditions[0].attr_code,
        proof.publicInputs[2].conditions[0].operator,
        proof.publicInputs[2].conditions[0].value,
        proof.publicInputs[2].conditions[0].issuer_codes[0],
        proof.publicInputs[2].predicates[0],

        proof.publicInputs[3][0].issuer_code,
        proof.publicInputs[3][0].public_key.x,
        proof.publicInputs[3][0].public_key.y,

        changeToHex(proof.publicInputs[0]),

        changeToHex(proof.publicInputs[1][0]),
    ];

    console.log(publicInputs);
    let verification1 = await vcpGenerationVerifier.verify(proof.proof, publicInputs);
    console.log(`on chain verification1: ${verification1}`);

    console.log(await singleProofVerifier.preparePublicInputs(0));

    let verification2 = await singleProofVerifier.verify(proof.proof, 0);
    console.log(`on chain verification2: ${verification2}`);

    return verification2;
}

function modifyInputsForContracts(testInput: any) {
    let conditions = Array();
    for (const condition of testInput.criteria.conditions) {
        conditions.push({
            attrCode: changeToHex(condition.attr_code),
            operator: condition.operator,
            value: condition.value,
            issuerCodes: [ changeToHex(condition.issuer_codes[0]) ],
        })
    }

    const requirement = {
        conditions: conditions,
        predicates: testInput.criteria.predicates,
    }

    console.log(requirement);

    let publicKeys = Array();
    for (const issuer of testInput.public_keys) {
        publicKeys.push({
            issuerCode: changeToHex(issuer.issuer_code),
            publicKey: issuer.public_key
        })
    }

    let revocationRoots = Array()
    for (const root of testInput.revocation_roots) {
        revocationRoots.push(changeToHex(root));
    }

    return {
        requirement,
        publicKeys,
        revocationRoots
    }
}

async function multiProofComputation(program: NoirProgram, options: NoirProgramOptions, testInput: any, verify = true): Promise<MyProofData> {
    const proof = await program.prove(testInput, options);

    if (verify) {
        const localVerification = await program.verify(proof, options);
        console.log(`local verification: ${localVerification}`);
    }

    return proof;
}

async function offChainComputation(circuitName: string, testInput: any, verify = true): Promise<MyProofData> {
    let options = getDefaultNoirProgramOptions();
    options.runningClient = NARGO;
    const program = await NoirProgram.createProgram(circuitName, options);
    const proof = await program.prove(testInput, options);

    if (verify) {
        const localVerification = await program.verify(proof, options);
        console.log(`local verification: ${localVerification}`);
    }

    return proof;
}

async function main() {
    const testInput = await generateTestInputs(2, 24);
    console.dir(testInput, {depth: null});

    // const singleVerification = await singleProofVerification(testInput);
    const multiVerification = await multiProofVerification(testInput);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
