import { HardhatUserConfig, vars } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ignition-ethers";
import "@openzeppelin/hardhat-upgrades";

import "./tasks/noir";

const POLYGON_MUMBAI_API_KEY = vars.get("POLYGON_MUMBAI_API_KEY")
const DEV_ACCOUNT_PRIVATE_KEY = vars.get("DEV_ACCOUNT_PRIVATE_KEY");


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
  networks: {
    polygon: {
      url: `https://polygon-mumbai.g.alchemy.com/v2/${POLYGON_MUMBAI_API_KEY}`,
      accounts: [`0x${DEV_ACCOUNT_PRIVATE_KEY}`]
    },
    iota: {
      url: `https://json-rpc.evm.testnet.shimmer.network/`,
      accounts: [`0x${DEV_ACCOUNT_PRIVATE_KEY}`]
    }
  }
};

export default config;
