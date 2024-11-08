import { HardhatUserConfig, vars } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ignition-ethers";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-gas-reporter";

import "./tasks/noir";

const POLYGON_MUMBAI_API_KEY = vars.get("POLYGON_MUMBAI_API_KEY")
const DEV_ACCOUNT_PRIVATE_KEY = vars.get("DEV_ACCOUNT_PRIVATE_KEY");
const HARDHAT_ACCOUNT_PRIVATE_KEY = vars.get("HARDHAT_ACCOUNT_PRIVATE_KEY")

const config: HardhatUserConfig = {
  solidity: {
    version:  "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      }
    }
  },
  gasReporter: {
    enabled: (process.env.REPORT_GAS) ? true : false
  },
  ignition: {
    blockPollingInterval: 1_000,
    timeBeforeBumpingFees: 3 * 60 * 1_000,
    maxFeeBumps: 4,
    requiredConfirmations: 1,
  },
  networks: {
    polygon: {
      url: `https://polygon-mumbai.g.alchemy.com/v2/${POLYGON_MUMBAI_API_KEY}`,
      accounts: [`0x${DEV_ACCOUNT_PRIVATE_KEY}`]
    },
    iota: {
      url: `https://json-rpc.evm.testnet.shimmer.network/`,
      accounts: [`0x${DEV_ACCOUNT_PRIVATE_KEY}`]
    },
    sepolia: {
      url: ``
    },
    local: {
      url: `http://127.0.0.1:8545/`,
      accounts: [HARDHAT_ACCOUNT_PRIVATE_KEY]
    }
  }
};

export default config;
