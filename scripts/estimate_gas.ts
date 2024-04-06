import hre from 'hardhat'
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import { ethers, ignition } from "hardhat";
import zkVCModule from "../ignition/modules/zkvc";
import { generateTestInputs, zkVCMode } from "./util/simulation";
import { MyProofData, NARGO, NoirProgram, NoirProgramOptions, getDefaultNoirProgramOptions } from "./util/noir_program";
import { boolean } from "mathjs";
import { changeToHex, prepareDataForMultiConditions, sleep, writeExpData } from "./util/data";
import { resolve } from 'path';
import { delay } from 'lodash';



async function multiProofVerification(testInput: any): Promise<number> {
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
    }

    const data = modifyInputsForContracts(testInput);

    await multiProofVerifier.updateRequirement(data.requirement, {publicKeys: data.publicKeys}, data.revocationRoots);


    multiProofVerifier.on("OnCondition", (i, p, j) => {
        console.log(`OnCondition: ${i}, ${p}, ${j}`);
    })

    multiProofVerifier.on("OnValidation", (i) => {
        console.log(`OnValidation: ${i}`);
    })

    // console.dir(testInput, {depth: null})
    // for (let i = 0; i < proofs.length; i++) {
    //     let onchainPublicInputs = await multiProofVerifier.preparePublicInputs(i, 0);

    //     // console.dir(subInputs[i], {depth: null})
    //     // console.dir(rawProofs[i].publicInputs, { depth: null });
    //     const proof = proofs[i];
    //     const rawProof = rawProofs[i];
    //     // console.log(proof);
    //     const offchainPublicInputs = [
    //         rawProof.publicInputs[2].conditions[0].attr_code,
    //         rawProof.publicInputs[2].conditions[0].operator,
    //         rawProof.publicInputs[2].conditions[0].value,
    //         rawProof.publicInputs[2].conditions[0].issuer_codes[0],
    //         rawProof.publicInputs[2].predicates[0],

    //         rawProof.publicInputs[3][0].issuer_code,
    //         rawProof.publicInputs[3][0].public_key.x,
    //         rawProof.publicInputs[3][0].public_key.y,

    //         changeToHex(rawProof.publicInputs[0]),

    //         changeToHex(rawProof.publicInputs[1][0]),
    //     ]

    //     console.log(onchainPublicInputs);
    //     console.log(offchainPublicInputs);

    //     let verification = await monoVcpGenerationVerifier.verify(proof, offchainPublicInputs);
    //     console.log(`on-chain mono-verification ${i}: ${verification}`);

    //     let verification2 = await multiProofVerifier.verifyCondition(proof, i, 0);
    //     console.log(`on-chain multi-verification ${i}: ${verification2}`);
    // }

    // const onChainPublicInputs = await multiProofVerifier.preparePublicInputs(0, 0);
    // console.dir(onChainPublicInputs, {depth: null});

    const verification = await multiProofVerifier.verify(proofs, 0);
    console.log(`on-chain multi verification: ${verification}`);

    const result = await multiProofVerifier.transfer(proofs, 0, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    // console.log(result);
    const receipt = await result.wait(1);
    // console.log(receipt);
    console.log(`price: ${receipt.gasUsed}`);

    return Number(receipt.gasUsed);
}

// function prepare

function preparePublicInputs(inputs: any): string[] {
    let publicInputs = Array<string>();

    for (const condition of inputs.criteria.conditions) {
        publicInputs.push(ethers.toBeHex(condition.attr_code, 32));
        publicInputs.push(ethers.toBeHex(condition.operator, 32));
        publicInputs.push(ethers.toBeHex(condition.value, 32));
        publicInputs.push(ethers.toBeHex(condition.issuer_codes[0], 32));
    }

    for (const p of inputs.criteria.predicates) {
        publicInputs.push(ethers.toBeHex(p, 32));
    }

    if (publicInputs.length > 29) {
        throw new Error("");

    }

    for (const pubKey of inputs.public_keys) {
        publicInputs.push(ethers.toBeHex(pubKey.issuer_code, 32));
        publicInputs.push(inputs.public_keys[0].public_key.x);
        publicInputs.push(inputs.public_keys[0].public_key.y);
    }

    publicInputs.push(ethers.toBeHex(inputs.proving_time, 32));

    for (const root of inputs.revocation_roots) {
        publicInputs.push(ethers.toBeHex(root, 32));
    }

    return publicInputs;
}

function comparePublicInputs(publicInputs1: any[], publicInputs2: any[]) {
    console.log(publicInputs1, {depth: null});
    console.log(publicInputs2, {depth: null});

    if (publicInputs1.length != publicInputs2.length) {
        throw new Error("length is different");
    }

    for (let i = 0; i < publicInputs1.length; i++) {
        if (publicInputs1[i] != publicInputs2[i]) {
            throw new Error(`different at i=${i} - ${publicInputs1[i]} - ${publicInputs2[i]}`);
        }
    }
}

async function singleProofVerification(inputData: any): Promise<number> {
    // console.dir(inputData, {depth: null});
    const data = modifyInputsForContracts(inputData);
    // console.dir(data, {depth: null});
    // const publicInputs = preparePublicInputs(inputData);

    const proof = await offChainComputation("vcp_generation", inputData, false);
    // console.dir(proof, {depth: null});

    const { singleProofVerifier, vcpGenerationVerifier } = await ignition.deploy(zkVCModule);

    await singleProofVerifier.updateRequirement(data.requirement, {publicKeys: data.publicKeys}, data.revocationRoots);

    // console.dir(`on-chain revocation roots: ${await singleProofVerifier.getRevocationTreeRoots()}`, {depth: null});

    // console.log(`on-chain requirement: ${await singleProofVerifier.getRequirement()}`);

    // console.dir(proof.publicInputs, {depth: null});

    // comparePublicInputs(publicInputs, await singleProofVerifier.preparePublicInputs(0));
    // console.log(publicInputs);
    // console.log(await singleProofVerifier.preparePublicInputs(0));

    // let verification1 = await vcpGenerationVerifier.verify(proof.proof, publicInputs);
    // console.log(`on chain verification1: ${verification1}`);

    // console.dir(`off-chain publicInputs: ${publicInputs}`);

    let verification2 = await singleProofVerifier.verify(proof.proof, 0);
    console.log(`on chain verification2: ${verification2}`);

    const result = await singleProofVerifier.transfer(proof.proof, 0, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    // console.log(result);
    const receipt = await result.wait(1);
    // console.log(receipt);
    console.log(`price: ${receipt.gasUsed}`);

    return Number(receipt.gasUsed);
}

function modifyInputsForContracts(testInput: any) {
    let conditions = Array();
    for (const condition of testInput.criteria.conditions) {
        let issuerId = 0;

        while(issuerId < testInput.public_keys.length) {
            if (condition.issuer_codes[0] == testInput.public_keys[issuerId].issuer_code) {
                break;
            }

            issuerId += 1;
        }

        conditions.push({
            attrCode: changeToHex(condition.attr_code),
            operator: condition.operator,
            value: condition.value,
            issuerIds: [ issuerId ],
        })
    }

    const requirement = {
        conditions: conditions,
        predicates: testInput.criteria.predicates,
    }

    // console.log(requirement);

    let publicKeys = Array();
    for (const issuer of testInput.public_keys) {
        publicKeys.push({
            issuerCode: changeToHex(issuer.issuer_code),
            publicKey: issuer.public_key
        });
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

async function writeResult(results: any[]) {
    const path = resolve(process.cwd())
}

async function main() {
    const args = {
        treeHeight: parseInt(process.env.h!),
        numConditions: parseInt(process.env.c!),
        mode: parseInt(process.env.m!) as zkVCMode,
        networkName: hre.network.name,
    };

    console.log(args);

    if (args.mode == zkVCMode.SingleProof) {
        const testInput = await generateTestInputs(args.numConditions, args.treeHeight);
        const gasUsed = await singleProofVerification(testInput);

        const expData = [{...args, gasUsed}];

        await writeExpData(expData, "onchain-ver", `onchain-${args.treeHeight}-${args.numConditions}-${args.mode}-${hre.network.name}`);
    } else {
        // let results = [];

        for(let i = 1; i <= args.numConditions; i++) {
            console.log(`numConditions=${i}`);
            const testInput = await generateTestInputs(i, args.treeHeight);
            let gasUsed = 0;

            while(true) {

                try {
                    gasUsed = await multiProofVerification(testInput);

                    break;
                } catch (error) {
                    const waitTime = 60000;
                    await sleep(waitTime);
                    console.log(`retry in ${waitTime/1000}s`);
                    continue
                }
            }


            const expData = [{...args, gasUsed, numConditions: i}];
            await writeExpData(expData, "onchain-ver", `onchain-${args.treeHeight}-${i}-${args.mode}-${hre.network.name}`);
        }
        // console.log(results);
    }
}

main().then(() => {
    console.log("Program completed.");
    process.exitCode= 0;
    process.exit();
}).catch((error) => {
    console.error(error);
    process.exitCode = 1;
    return;
});
