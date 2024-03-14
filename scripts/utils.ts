import childProcess from "node:child_process";
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

class MyProofData {
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

    console.log(myProjectPath)

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
    const proof = await this.noir!.generateFinalProof(inputData);

    return proof;
  }

  public async prove(inputData: any, options?: NoirProgramOptions): Promise<MyProofData> {
    if (options === undefined) {
      options = this.options;
    }

    if (options!.isJSProving) {
      return MyProofData.fromNoirProofData(await this.proveNoirJS(inputData));
    } else {
      return this.proveCLI(inputData, options);
    }
  }

  async verifyNoirJS(proofData: MyProofData): Promise<boolean> {
    const verification = await this.noir!.verifyFinalProof(proofData.toNoirProofData());
    return verification;
  }

  async verifyCLI(proofData: MyProofData, options?: NoirProgramOptions): Promise<boolean> {
    try {
      const circuitDirPath = getCircuitDirPath(this.name);
      const command = `nargo verify --verifier-name ${options?.verifierName!}`;
      console.log(`executing ${command}`);

      console.time("verifying");
      childProcess.execSync(command, {
        cwd: circuitDirPath,
      })
      console.timeEnd("verifying");

      return true;
    } catch (error) {
      return false;
    }
  }

  public async verify(proofData: MyProofData, options?: NoirProgramOptions): Promise<boolean> {
    if (options === undefined) {
      options = this.options;
    }

    if (options!.isJSProving) {
      return this.verifyNoirJS(proofData);
    } else {
      return this.verifyCLI(proofData, options);
    }
  }

  public async generateInputs(inputData: any, options?: NoirProgramOptions) {
    const inputPath = resolve(getCircuitDirPath(this.name), `${options?.proverName}.toml`);
    fs.writeFileSync(inputPath, toml.stringify(inputData));
    console.log(`Generated input at ${inputPath}`);
  }

  public async proveCLI(inputData: any, options?: NoirProgramOptions): Promise<MyProofData> {
    await this.generateInputs(inputData, options);
    const circuitDirPath = getCircuitDirPath(this.name);
    const command = `nargo prove --prover-name ${options?.proverName!}`;

    console.log(`executing ${command}`);

    console.time("proving");
    childProcess.execSync(command, {
      cwd: circuitDirPath,
    })
    console.timeEnd("proving");

    // read the circuit proof
    const proofFilePath = resolve(circuitDirPath, "proofs", `${this.name}.proof`);
    const publicInputFilePath = resolve(circuitDirPath, `${options?.verifierName}.toml`);

    return new Promise((resolve, reject) => {
      resolve(MyProofData.fromFiles(proofFilePath, publicInputFilePath));
    });
  }
}
