import { BackendOptions, BarretenbergBackend, ProofData } from "@noir-lang/backend_barretenberg";
import { Noir } from "@noir-lang/noir_js";
import { compile, createFileManager } from "@noir-lang/noir_wasm";
import { ProgramArtifact, ProgramCompilationArtifacts } from "@noir-lang/noir_wasm/dist/types/src/types/noir_artifact";
import { resolve } from "path";

export class NoirProgram {
  name: string;
  options?: BackendOptions;
  noir?: Noir;
  backend?: BarretenbergBackend;
  compiledCode?: ProgramArtifact;

  constructor(circuitName: string, options?: BackendOptions) {
    this.name = circuitName;
    this.options = options;
  }

  public static async createProgram(circuitName: string, options?: BackendOptions) {
    const program = new NoirProgram(circuitName, options);

    const myProjectPath = resolve(__dirname, "..", "circuits", circuitName);
    const fm = createFileManager(resolve(myProjectPath));
    program.compiledCode = ((await compile(fm)) as ProgramCompilationArtifacts).program;

    program.backend = new BarretenbergBackend(program.compiledCode!, program.options);
    program.noir = new Noir(program.compiledCode!, program.backend);

    return program;
  }

  public async prove(inputData: any): Promise<ProofData> {
    const proof = await this.noir!.generateFinalProof(inputData);

    return proof;
  }
  public async verify(proofData: ProofData): Promise<boolean> {
    const verification = await this.noir!.verifyFinalProof(proofData);

    return verification;
  }
}
