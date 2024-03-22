import { max, mean, std } from "mathjs";
import pidusage from "pidusage";
import childProcess, { ChildProcess } from "node:child_process";
import toml from '@iarna/toml';
import { BackendOptions, BarretenbergBackend, ProofData } from "@noir-lang/backend_barretenberg";
import { Noir } from "@noir-lang/noir_js";
import { compile, createFileManager } from "@noir-lang/noir_wasm";
import { ProgramArtifact, ProgramCompilationArtifacts } from "@noir-lang/noir_wasm/dist/types/src/types/noir_artifact";
import { resolve } from "path";
import fs from "fs";
import { bufferToBigint, bigNumberishToBigint, bigintToBuffer, bigintToHexadecimal } from "@zk-kit/utils";
import { Proof } from "viem/_types/types/proof";
import { hexToBigInt, hexToBytes } from "viem";
import { bigIntToHex, bytesToHex } from "@nomicfoundation/ethereumjs-util";
import { hexlify } from "ethers";

const TREE_DEPTH = 256;

function getCircuitDirPath(circuitName: string): string {
  return resolve(__dirname, "..", "circuits", circuitName);
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

  static fromFiles(proofFilePath: string, publicInputFilePath: string): MyProofData {
    const proof = `0x${fs.readFileSync(proofFilePath, "utf8")}`;

    let publicInputValues = Array<string>();
    const publicInputs = toml.parse(fs.readFileSync(publicInputFilePath).toString("utf8"));
    for (const name in publicInputs) {
      publicInputValues.push(publicInputs[name] as string);
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
  isJSProving?: boolean;
  isJSVerying?: boolean;
  proverName?: string;
  verifierName?: string;
}

export function getDefaultNoirProgramOptions() {
  return {
    threads: 8,
    compiled: false,
    isJSProving: false,
    proverName: "Prover",
    verifierName: "Verifier",
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
}

async function executeAndMeasureStats(command: string, options: { cwd: string, debug: boolean, interval: number, commandName: string }): Promise<PerformanceStat> {
  const myChildProcess = childProcess.exec(command, { cwd: options.cwd });

  // console.log(`executing ${command}`);
  let memoryUsages: number[] = [];
  let startTime = (new Date()).getTime();

  while (true) {
    try {
      await delay(options.interval);
      const temp = await pidusage(myChildProcess.pid!);

      memoryUsages.push(temp.memory);

      // if (options.debug) {
      //   console.log(temp);
      // }
    } catch (error) {
      break;
    }
  }

  let duration = (new Date()).getTime() - startTime;

  let maxMemoryUsage = max(memoryUsages);
  let meanMemoryUsage = mean(memoryUsages);
  let stdMemoryUsage = std(memoryUsages, "unbiased") as number;

  return {
    name: options.commandName,
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

    if (options!.isJSProving) {
      if (options!.compiled) {
        program.compiledCode = require(resolve(myProjectPath, "target", `${circuitName}.json`));
      } else {
        const fm = createFileManager(resolve(myProjectPath));
        program.compiledCode = ((await compile(fm)) as ProgramCompilationArtifacts).program;
      }

      program.backend = new BarretenbergBackend(program.compiledCode!, { threads: program.options!.threads! });
      program.noir = new Noir(program.compiledCode!, program.backend);
    }

    return program;
  }

  public async proveNoirJS(inputData: any): Promise<ProofData> {
    const proof = await this.noir!.generateProof(inputData);
    return proof;
  }

  public async proveCLI(inputData: any, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData> {
    await this.generateInputs(inputData, options);
    const circuitDirPath = getCircuitDirPath(this.name);
    const command = `nargo prove --prover-name ${options?.proverName!}`;

    // console.time("NoirProgram:proveCLI:prove");
    const stat = await executeAndMeasureStats(command, { cwd: circuitDirPath, debug: false, interval: 1000, commandName: "proveCLI" });
    // console.timeEnd("NoirProgram:proveCLI:prove");
    // console.log("proving stats: ", stat);

    // read the circuit proof
    const proofFilePath = resolve(circuitDirPath, "proofs", `${this.name}.proof`);
    const publicInputFilePath = resolve(circuitDirPath, `${options?.verifierName}.toml`);

    stats!.push(stat);
    return new Promise((resolve, reject) => {
      resolve(MyProofData.fromFiles(proofFilePath, publicInputFilePath));
    });
  }

  public async prove(inputData: any, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<MyProofData> {
    if (options === undefined) {
      options = this.options;
    }

    // console.time("NoirProgram:prove");
    if (options!.isJSProving) {
      return MyProofData.fromNoirProofData(await this.proveNoirJS(inputData));
    } else {
      return this.proveCLI(inputData, options, stats);
    }
    // console.timeEnd("NoirProgram:prove");
  }

  async verifyNoirJS(proofData: MyProofData): Promise<boolean> {
    const verification = await this.noir!.verifyProof(proofData.toNoirProofData());
    return verification;
  }

  async verifyCLI(proofData: MyProofData, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<boolean> {
    try {
      const circuitDirPath = getCircuitDirPath(this.name);
      const command = `nargo verify --verifier-name ${options?.verifierName!}`;

      // console.time("verifying");
      const stat = await executeAndMeasureStats(command, { cwd: circuitDirPath, interval: 1000, debug: false, commandName: "verifyCLI" });
      // console.timeEnd("verifying");
      // console.log("verifying stats: ", stat);

      stats!.push(stat);
      return true;
    } catch (error) {
      return false;
    }
  }

  public async verify(proofData: MyProofData, options?: NoirProgramOptions, stats?: PerformanceStat[]): Promise<boolean> {
    if (options === undefined) {
      options = this.options;
    }

    if (options!.isJSProving) {
      return this.verifyNoirJS(proofData);
    } else {
      return this.verifyCLI(proofData, options, stats);
    }
  }

  public async generateInputs(inputData: any, options?: NoirProgramOptions) {
    const inputPath = resolve(getCircuitDirPath(this.name), `${options?.proverName}.toml`);
    fs.writeFileSync(inputPath, toml.stringify(inputData));
    // console.log(`Generated input at ${inputPath}`);
  }
}
