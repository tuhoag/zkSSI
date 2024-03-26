import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ZKVC", (m) => {
  const vcpGenerationVerifier = m.contract("VcpGenerationVerifier");
  const singleProofVerifier = m.contract("SingleProofVerifier", ["Verifier01", vcpGenerationVerifier]);

  const monoVcpGenerationVerifier = m.contract("MonoVcpGenerationVerifier");
  const multiProofVerifier = m.contract("MultiProofVerifier", ["Verifier02", monoVcpGenerationVerifier]);

  return { singleProofVerifier, multiProofVerifier, vcpGenerationVerifier, monoVcpGenerationVerifier };
});