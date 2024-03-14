import { scope, subtask, task } from "hardhat/config";

import fs from "fs";
import path from "path";

import { execSync } from "child_process";

const noirScope = scope("noir", "Manage Noir utilities");
const circuitsDir = path.join(__dirname, `../circuits/`);

noirScope.task("generate-verifier-contract", "Generate Noir circuit verifier contract and copy it to the contracts folder.")
.addParam("circuit", "The name of the circuit to create a contract for")
.setAction(async (taskArgs, hre) => {
  await generateVerifierContract(taskArgs, hre);
});

noirScope.task("generate-circuit", "Generate Noir circuit.")
.addParam("circuit", "The name of the circuit to create a contract for")
.setAction(async (taskArgs, hre) => {
  await generateCircuit(taskArgs, hre);
});

noirScope.task("compile-circuit", "Compile Noir circuit.")
.addParam("circuit", "The name of the circuit to create a contract for")
.setAction(async (taskArgs, hre) => {
  await compileCircuit(taskArgs, hre);
});

function snakeToCamel(snake: string): string {
  let result = snake.split('').reduce((prev: string, cur: string) => {
    if (prev.includes("_")) {
      prev = prev.substring(0, prev.length - 1);
      cur = cur.toUpperCase();
    }
    return prev + cur;
  }, "");

  return `${result.charAt(0).toUpperCase()}${result.slice(1)}`;
  // return `${result.charAt[0].toUpperCase()}${result.slice(1)}`;
}

async function generateVerifierContract(taskArgs: any, hre: any) {
  const { circuit } = taskArgs;

  if (!circuit) throw new Error("Need a circuit name!");

  const currentCircuitDir = path.join(circuitsDir, circuit);

  if (!fs.existsSync(currentCircuitDir))
    throw new Error("Somethings gone wrong with the directory");

  const codegenVerifierCommand = `cd ${currentCircuitDir} && nargo compile && nargo codegen-verifier`;

  execSync(codegenVerifierCommand);

  // we now have a plonk_vk.sol at circuits/myCircuit/contracts/, we need to rename it
  // to the name of our circuit + Verifier.sol and place it in our contracts/ directory

  const oldPath = `${currentCircuitDir}/contract/${circuit}/plonk_vk.sol`;
  const contractsDir = path.join(__dirname, "../contracts");


  const capitalisedCircuitName = snakeToCamel(circuit);

  const newPath = `${contractsDir}/${capitalisedCircuitName}Verifier.sol`;

  // move the circuit contract from the circuits/ directory to the contracts/ directory
  fs.copyFileSync(oldPath, newPath);
  // delete the circuitName/contract directory (not needed)
  fs.rmdirSync(`${currentCircuitDir}/contract/`, { recursive: true });

  // now we need to update the contract to have the correct contract name
  // read the file contents
  const fileContents = fs.readFileSync(newPath, "utf8");

  // in keeping with my solidity naming convention, we need to make sure the contracts first letter is capitalised
  // plus we need to update the verify function to not have the _proof param name (throws an unused param error)
  const newFileContents = fileContents
    .replace(
      "contract UltraVerifier is ",
      `contract ${capitalisedCircuitName}Verifier is `
    )
    .replace(
      "* @param _proof - The serialized proof",
      "* bytes calldata - The serialized proof (this isn't named cause accessed with assembly)"
    )
    .replace(
      "function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool) {",
      "function verify(bytes calldata, bytes32[] calldata _publicInputs) external view returns (bool) {"
    );

  fs.writeFileSync(newPath, newFileContents, "utf8");

  console.log(
    `Successfully added ${capitalisedCircuitName} contract to contracts/ directory`
  );
};

async function generateCircuit(taskArgs: any, hre: any) {
  const { circuit } = taskArgs;

  if (!circuit) throw new Error("Need a circuit name!");

  const currentCircuitDir = path.join(circuitsDir, circuit);

  if (!fs.existsSync(circuitsDir)) {
    // create the folder if it is not existed
    fs.mkdirSync(circuitsDir);
  }

  const circuitGenCommand = `cd ${circuitsDir} && nargo new ${circuit}`;
  execSync(circuitGenCommand);

  console.log(
    `Successfully created ${circuit} circuit to ${currentCircuitDir} directory`
  );
}

async function compileCircuit(taskArgs: any, hre: any) {
  const { circuit } = taskArgs;

  if (!circuit) throw new Error("Need a circuit name!");

  const currentCircuitDir = path.join(circuitsDir, circuit);

  if (!fs.existsSync(currentCircuitDir)) {
    // create the folder if it is not existed
    throw new Error("Somethings gone wrong with the directory");
  }

  const circuitCompileCommand = `cd ${currentCircuitDir} && nargo compile`;
  execSync(circuitCompileCommand);

  console.log(
    `Successfully compiled ${circuit} in ${currentCircuitDir} directory`
  );
}