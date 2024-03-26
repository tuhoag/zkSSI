import fs from "fs";
import { resolve } from "path";
import { SMT } from 'circomlibjs';
import { bigIntToHex } from "@nomicfoundation/ethereumjs-util";
import { createSMT as createSparseMerkleTree } from "./util/circom_smt_utils";
import { MyProofData, NoirProgram, NoirProgramOptions, PerformanceStat, aggregatePerformanceStats, getDefaultNoirProgramOptions } from "./util/noir_program";
import { generateTestInputs, zkVCMode } from "./util/simulation";
import { MerkleTreeProof, prepareDataForMultiConditions } from "./util/data";


export async function executeSingleProofMultiConditions(program: NoirProgram, inputs: any, options: NoirProgramOptions): Promise<PerformanceStat[]> {
    let performanceStats: PerformanceStat[] = [];
    // const program = await NoirProgram.createProgram("vcp_generation", options);

    // console.dir(inputs, {depth: null});
    // throw new Error("");

    console.time("prove");
    const proof = await program.prove(inputs, options, performanceStats);
    console.timeEnd("prove");
    // console.dir(proof, {depth: null});
    // console.log(bigIntToHex(proof.proof));


    console.time("verify");
    const verification = await program.verify(proof, options, performanceStats);
    console.timeEnd("verify");
    console.dir(`off-chain verification: ${verification}`, { depth: null });

    return performanceStats
}




export async function generateProofsForMultiConditions(program: NoirProgram, inputs: any, options: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData[]> {
    let performanceStats = Array<PerformanceStat>();
    let proofs = Array<MyProofData>();
    // const options = getDefaultNoirProgramOptions();
    // const program = await NoirProgram.createProgram("mono_vcp_generation", options);
    const subInputs = prepareDataForMultiConditions(inputs);
    for(const subInput in subInputs) {
        const proof = await program.prove(subInput, options, performanceStats);
        proofs.push(proof);
    }

    let aggStat = aggregatePerformanceStats(performanceStats);
    aggStat.name = performanceStats[0].name;
    stats!.push(aggStat);

    return proofs;
}

export async function verifyProofsForMultiConditions(program: NoirProgram, inputs: any, options: NoirProgramOptions, proofs: MyProofData[], stats?: PerformanceStat[]): Promise<boolean> {
    const predicates = inputs.criteria.predicates;
    // const options = getDefaultNoirProgramOptions();
    // const program = await NoirProgram.createProgram("mono_vcp_generation", options);

    let validations = Array<boolean>();
    for(let i = 0; i < predicates.length; i++) {
        validations.push(false);
    }

    let performanceStats = Array<PerformanceStat>();

    for(let i = predicates.length - 1; i >= 0; i--) {
        const left = i * 2 + 1;
        const right = i * 2 + 2;
        // const inverseLeft = predicates.length - left - 1;
        // const inverseRight = predicates.length - right - 1;
        // console.log(`i: ${i} - left=${left} - right=${right}`);

        if (predicates[i] == 0) {
            validations[i] = validations[left] && validations[right];
        } else if (predicates[i] == 1) {
            validations[i] = validations[left] || validations[right];
        } else if (predicates[i] >= 2) {
            // verify
            const proof = proofs[predicates[i] - 2];
            const verification = await program.verify(proof, options, performanceStats);
            // validations.push(verification);
            validations[i] = verification;
        } else {
            throw new Error(`Predicate ${predicates[i]} is invalid`);
        }

        // console.log(predicates[i]);
        // console.log(validations);
    }

    let aggStat = aggregatePerformanceStats(performanceStats);
    aggStat.name = performanceStats[0].name;
    stats!.push(aggStat);

    // console.log(validations);
    // throw new Error("");

    // console.log(validations[0]);
    // throw new Error("");

    return validations[0];
}

async function executeMultiProofMultiConditions(program: NoirProgram, inputs: any, options: NoirProgramOptions): Promise<PerformanceStat[]> {
    let performanceStats: PerformanceStat[] = [];

    // generate proofs for each condition
    // options. = "prove";

    console.time("prove");
    const proofs = await generateProofsForMultiConditions(program, inputs, options, performanceStats);
    console.timeEnd("prove");

    // verify proofs according to predicates
    // option
    console.time("verify");
    const verification = await verifyProofsForMultiConditions(program, inputs, options, proofs, performanceStats);
    console.timeEnd("verify");

    console.dir(`off-chain verification: ${verification}`, { depth: null });

    return performanceStats
}

async function writeExpData(expData: any[], name: string) {
    const expDataPath = resolve(__dirname, "..", "reports", "data", `${name}.json`);
    fs.writeFileSync(expDataPath, JSON.stringify(expData));
    console.log(`wrote exp data to ${expDataPath}`);
}

function getCircuitName(mode: zkVCMode) {
    if (mode == zkVCMode.SingleProof) {
        return "vcp_generation";
    } else {
        return "mono_vcp_generation";
    }
}

async function evaluateASetting(treeHeight: number, numConditions: number, mode: zkVCMode) {
    let expData = [];
    const numTrials = 3;
    let options = getDefaultNoirProgramOptions();
    const circuitName = getCircuitName(mode);
    const program = await NoirProgram.createProgram(circuitName, options);

    for (let trial = 0; trial < numTrials; trial++) {
        console.log(`Setting: treeHeight=${treeHeight} - numConditions=${numConditions} - trial=${trial} - mode=${mode}`);
        const inputs = await generateTestInputs(numConditions, treeHeight);

        let currentStats:PerformanceStat[];

        if (mode == zkVCMode.SingleProof) {
            options.expName = "SingleProof";
            currentStats = await executeSingleProofMultiConditions(program, inputs, options);
        } else if (mode == zkVCMode.MultiProof) {
            options.expName = "MultiProof";
            currentStats = await executeMultiProofMultiConditions(program, inputs, options);
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

    await writeExpData(expData, `offchain-${treeHeight}-${numConditions}-${mode}-${options.runningClient}`);
}

async function evaluate(args: {treeHeight: number, numConditions: number, mode: zkVCMode}) {
    const { treeHeight, numConditions, mode } = args;

    if (mode == zkVCMode.SingleProof) {
        await evaluateASetting(treeHeight, numConditions, mode);
    } else if (mode == zkVCMode.MultiProof) {
        for (let curNumConditions = 9; curNumConditions <= numConditions; curNumConditions ++) {
            await evaluateASetting(treeHeight, curNumConditions, mode);
        }
    } else {
        throw new Error(`Unsupported running mode: ${mode}`);
    }
}

async function main() {
    const args = {
        treeHeight: parseInt(process.env.h!),
        numConditions: parseInt(process.env.c!),
        mode: parseInt(process.env.m!) as zkVCMode,
    };

    // console.log(args);
    // console.log(args.mode == zkVCMode.SingleProof);
    // console.log(process.env.h, process.env.c, process.env.m);
    // throw new Error("");

    evaluate(args);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
