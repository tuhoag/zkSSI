import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ZKVC", (m) => {
  const ownerAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

  const vcpGenerationVerifier = m.contract("VcpGenerationVerifier");
  const singleProofVerifier = m.contract("SingleProofVerifier", ["Verifier01", vcpGenerationVerifier, ownerAddress]);

  const monoVcpGenerationVerifier = m.contract("MonoVcpGenerationVerifier");
  const multiProofVerifier = m.contract("MultiProofVerifier", ["Verifier02", monoVcpGenerationVerifier, ownerAddress]);

  return { singleProofVerifier, multiProofVerifier, vcpGenerationVerifier, monoVcpGenerationVerifier };
});