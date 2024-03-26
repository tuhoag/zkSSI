// import { scope, subtask, task } from "hardhat/config";

// import fs from "fs";
// import path from "path";

// import { execSync } from "child_process";

// const noirScope = scope("zkvc", "Manage zkVC utilities");

// noirScope.task("generate-verifier-contract", "Generate Noir circuit verifier contract and copy it to the contracts folder.")
// .addParam("circuit", "The name of the circuit to create a contract for")
// .setAction(async (taskArgs, hre) => {
//   await generateVerifierContract(taskArgs, hre);
// });

// noirScope.task("generate-circuit", "Generate Noir circuit.")
// .addParam("circuit", "The name of the circuit to create a contract for")
// .setAction(async (taskArgs, hre) => {
//   await generateCircuit(taskArgs, hre);
// });

// noirScope.task("compile-circuit", "Compile Noir circuit.")
// .addParam("circuit", "The name of the circuit to create a contract for")
// .setAction(async (taskArgs, hre) => {
//   await compileCircuit(taskArgs, hre);
// });