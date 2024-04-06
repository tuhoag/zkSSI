import childProcess, { ChildProcess } from "node:child_process";
import toml from '@iarna/toml';
import { resolve } from "path";
import { bytesToHex } from "@nomicfoundation/ethereumjs-util";
import fs from "fs";
import { Noir, ProofData } from "@noir-lang/noir_js";
import { bigintToBuffer } from '@zk-kit/utils';
import pidusage from "pidusage";
import { max, mean, std } from "mathjs";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import { ProgramArtifact, ProgramCompilationArtifacts } from "@noir-lang/noir_wasm/dist/types/src/types/noir_artifact";
import { compile, createFileManager } from "@noir-lang/noir_wasm";

export const NOIR_JS = "noir_js";
export const NARGO = "nargo";
export const NOIR_RS = "noir_rs";

function getCircuitDirPath(circuitName: string): string {
    return resolve(process.cwd(), "circuits", circuitName);
}

function getNoirRSPath(): string {
    return resolve(process.cwd(), "target", "debug", "circuit_clients");
}

export class MyProofData {
    publicInputs: string[];
    proof: string;

    constructor(proof: string, publicInputs: string[]) {
        this.proof = proof;
        this.publicInputs = publicInputs;
    }

    static fromNoirProofData(proofData: ProofData): MyProofData {
        let publicInputs = Array<string>();

        for (const item of proofData.publicInputs) {
            publicInputs.push(item);
        }

        return new MyProofData(
            bytesToHex(proofData.proof as Buffer),
            publicInputs
        );
    }

    static fromFiles(proofFilePath: string, publicInputFilePath?: string): MyProofData {
        const proof = `0x${fs.readFileSync(proofFilePath, "utf8")}`;

        let publicInputValues = Array<string>();
        if (publicInputFilePath !== undefined) {

            const publicInputs = toml.parse(fs.readFileSync(publicInputFilePath).toString("utf8"));
            for (const name in publicInputs) {
                publicInputValues.push(publicInputs[name] as string);
            }
        }

        return new MyProofData(proof, publicInputValues);
    }

    toNoirProofData(): ProofData {


        return {
            proof: bigintToBuffer(BigInt(this.proof)),
            publicInputs: this.publicInputs
        };
    }
}
export type NoirProgramOptions = {
    threads?: number;
    compiled?: boolean;
    runningClient: string;
    expName: string,
    isJSVerying: boolean;
    proverName?: string;
    verifierName?: string;
    interval: number;
}

export function getDefaultNoirProgramOptions(): NoirProgramOptions {
    return {
        threads: 8,
        compiled: false,
        runningClient: NARGO,
        isJSVerying: false,
        proverName: "Prover",
        verifierName: "Verifier",
        expName: "",
        interval: 10,
    };
}

function delay(time: number) {
    return new Promise(resolve => setTimeout(resolve, time));
}

export type PerformanceStat = {
    name: string;
    executionTime: number;
    peakMemoryUsage: number;
    meanMemoryUsage: number;
    stdMemoryUsage: number;
    step: string,
    client: string,
}

async function executeAndMeasureStats(command: string, options: { cwd: string, debug: boolean, interval: number, expName: string, client: string, step: string }): Promise<PerformanceStat> {
    console.log(`executing ${command} at ${options.cwd}`);

    const myChildProcess = childProcess.exec(command, { cwd: options.cwd });

    let isError = false;
    let startTime = (new Date()).getTime();
    let duration = 0;
    // let isFinished = false;
    myChildProcess.on('exit', (code, signal) => {
        if (code != 0) {
            console.log(code);
        }

        // console.log(signal);
        if (code != 0) {
            isError = true;
        }

        // isFinished = true;
        duration = (new Date()).getTime() - startTime;
    });

    myChildProcess.on('error', (err) => {
        console.log("\n\t\tERROR: spawn failed! (" + err + ")");
        isError = true;
    });


    let memoryUsages: number[] = [];

    let temp;
    while (true) {
        try {
            await delay(options.interval);
            temp = await pidusage(myChildProcess.pid!);
            // console.log(temp);
            memoryUsages.push(temp.memory);

        } catch (error) {
            if (isError) {
                throw new Error(`Cannot execute command: ${command} with error: ${error}`);
            }
            break;
        }
    }

    // console.log(temp);
    // console.log(memoryUsages);
    // throw new Error("");


    // console.log(duration);
    let maxMemoryUsage = 0;
    let meanMemoryUsage = 0;
    let stdMemoryUsage = 0;

    if (memoryUsages.length != 0) {
        maxMemoryUsage = max(memoryUsages);
        meanMemoryUsage = mean(memoryUsages);
        stdMemoryUsage = std(memoryUsages, "unbiased") as number;
    }

    return {
        name: options.expName,
        step: options.step,
        client: options.client,
        executionTime: duration,
        peakMemoryUsage: maxMemoryUsage,
        meanMemoryUsage: meanMemoryUsage,
        stdMemoryUsage: stdMemoryUsage
    }
}

export class NoirProgram {
    name: string;
    options?: NoirProgramOptions;
    noir?: Noir;
    backend?: BarretenbergBackend;
    compiledCode?: ProgramArtifact;
    stats?: Map<string, number>;

    constructor(circuitName: string, options?: NoirProgramOptions) {
        this.name = circuitName;
        this.options = options;
        this.stats = new Map();
    }

    public static async createProgram(circuitName: string, options?: NoirProgramOptions) {
        const program = new NoirProgram(circuitName, options);

        const myProjectPath = getCircuitDirPath(circuitName);

        if (options!.runningClient == NOIR_JS) {
            if (options!.compiled) {
                program.compiledCode = require(resolve(myProjectPath, "target", `${circuitName}.json`));
            } else {
                const fm = createFileManager(resolve(myProjectPath));
                program.compiledCode = ((await compile(fm)) as ProgramCompilationArtifacts).program;
            }

            program.backend = new BarretenbergBackend(program.compiledCode!, { threads: program.options!.threads! });
            program.noir = new Noir(program.compiledCode!, program.backend);
        } else if (options!.runningClient == NOIR_RS) {
            const circuitDirPath = getCircuitDirPath(circuitName);
            const command = `nargo compile`;

            await executeAndMeasureStats(command, { cwd: circuitDirPath, debug: false, interval: options!.interval, expName: options!.expName, client: options!.runningClient, step: "prove" });

            await executeAndMeasureStats(`cargo build`, { cwd: process.cwd(), debug: false, interval: options!.interval, expName: options!.expName, client: options!.runningClient, step: "prove" });

        }

        return program;
    }

    public async proveNoirJS(inputData: any): Promise<ProofData> {
        const proof = await this.noir!.generateProof(inputData);
        return proof;
    }

    public async proveCLI(inputData: any, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData> {
        // console.dir(inputData, {depth: null});
        // throw new Error("");

        await this.generateInputs(inputData, options);
        const circuitDirPath = getCircuitDirPath(this.name);
        const command = `nargo prove --prover-name ${options?.proverName!}`;

        // console.time("NoirProgram:proveCLI:prove");
        const stat = await executeAndMeasureStats(command, { cwd: circuitDirPath, debug: false, interval: options!.interval, expName: options!.expName, client: options!.runningClient, step: "prove" });
        // console.timeEnd("NoirProgram:proveCLI:prove");
        // console.log("proving stats: ", stat);

        // read the circuit proof
        const proofFilePath = resolve(circuitDirPath, "proofs", `${this.name}.proof`);
        const publicInputFilePath = resolve(circuitDirPath, `${options?.verifierName}.toml`);

        if (stats !== undefined) {
            stats!.push(stat);
        }

        return new Promise((resolve, reject) => {
            resolve(MyProofData.fromFiles(proofFilePath, publicInputFilePath));
        });
    }

    public async proveNoirRS(inputData: any, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData> {
        await this.generateInputs(inputData, options);
        const clientPath = getNoirRSPath();

        const command = `${clientPath} --circuit ${this.name} --mode prove`;
        // console.log("proveNoirRS")
        // console.time("NoirProgram:proveCLI:prove");
        const stat = await executeAndMeasureStats(command, { cwd: process.cwd(), debug: false, interval: options!.interval, client: options!.runningClient, expName: options!.expName, step: "prove" });
        // console.timeEnd("NoirProgram:proveCLI:prove");
        // console.log("proving stats: ", stat);
        // console.log(stat);
        // throw new Error("");

        // read the circuit proof
        const circuitDirPath = getCircuitDirPath(this.name);
        const proofFilePath = resolve(circuitDirPath, "proofs", `myproof.proof`);
        // const publicInputFilePath = resolve(circuitDirPath, `${options?.verifierName}.toml`);

        stats!.push(stat);
        return new Promise((resolve, reject) => {
            resolve(MyProofData.fromFiles(proofFilePath));
        });
    }

    public async prove(inputData: any, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData> {
        if (options === undefined) {
            options = this.options;
        }

        // console.log(options);

        // throw new Error("");

        // console.time("NoirProgram:prove");
        if (options!.runningClient == NOIR_JS) {
            return MyProofData.fromNoirProofData(await this.proveNoirJS(inputData));
        } else if (options!.runningClient == NARGO) {
            return this.proveCLI(inputData, options, stats);
        } else if (options!.runningClient == NOIR_RS) {
            return this.proveNoirRS(inputData, options, stats);
        } else {
            throw new Error(`Non supported running client ${options!.runningClient}`);
        }
        // console.timeEnd("NoirProgram:prove");
    }

    async verifyNoirJS(proofData: MyProofData): Promise<boolean> {
        const verification = await this.noir!.verifyProof(proofData.toNoirProofData());
        return verification;
    }

    async verifyNoirRS(proofData: MyProofData, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<boolean> {
        try {
            const clientPath = getNoirRSPath();
            const command = `${clientPath} --circuit ${this.name} --mode verify`;
            // throw new Error("");
            // console.time("verifying");
            const stat = await executeAndMeasureStats(command, { cwd: process.cwd(), interval: options!.interval, debug: false, client: options!.runningClient, step: "verify", expName: options!.expName });
            // console.timeEnd("verifying");
            // console.log("verifying stats: ", stat);

            stats!.push(stat);
            return true;
        } catch (error) {
            console.log(`verification error: ${error}`);
            return false;
        }
    }

    async verifyCLI(proofData: MyProofData, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<boolean> {
        try {
            const circuitDirPath = getCircuitDirPath(this.name);
            const command = `nargo verify --verifier-name ${options!.verifierName!}`;

            // console.time("verifying");
            const stat = await executeAndMeasureStats(command, { cwd: circuitDirPath, interval: options!.interval, debug: false, client: options!.runningClient, step: "verify", expName: options!.expName });
            // console.timeEnd("verifying");
            // console.log("verifying stats: ", stat);

            if (stats !== undefined) {
                stats!.push(stat);
            }

            return true;
        } catch (error) {
            return false;
        }

        return false;
    }

    public async verify(proofData: MyProofData, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<boolean> {
        if (options === undefined) {
            options = this.options;
        }
        // console.log(options!.runningClient);

        if (options!.runningClient == NOIR_JS) {
            return this.verifyNoirJS(proofData);
        } else if (options!.runningClient == NARGO) {
            return this.verifyCLI(proofData, options, stats);
        } else if (options!.runningClient == NOIR_RS) {
            return this.verifyNoirRS(proofData, options, stats);
        } else {
            throw new Error(`Non supported running client ${options!.runningClient}`);
        }
    }

    public async generateInputs(inputData: any, options?: NoirProgramOptions) {
        // console.dir(inputData, {depth: null});
        const inputPath = resolve(getCircuitDirPath(this.name), `${options?.proverName}.toml`);
        // console.log(inputData);
        fs.writeFileSync(inputPath, toml.stringify(inputData));
        console.log(`Generated input at ${inputPath}`);
    }
}

export function aggregatePerformanceStats(stats: PerformanceStat[]): PerformanceStat {
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
        step: stats[0].step,
        client: stats[0].client,
        executionTime: totalExecutionTime,
        peakMemoryUsage: maxPeakMemoryUsage,
        meanMemoryUsage: meanMeanMemoryUsage / stats.length,
        stdMemoryUsage: meanStdMemoryUsage / stats.length,
    }
}
