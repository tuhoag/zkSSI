import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ZKVC", (m) => {
  const vcpVerifierContract = m.contract("VcpGenerationVerifier");

  return { vcpVerifierContract };
});