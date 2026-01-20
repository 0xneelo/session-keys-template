const hre = require("hardhat");

async function main() {
  console.log("Deploying GasSponsor contract...\n");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer address:", deployer.address);
  
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer balance:", hre.ethers.formatEther(balance), "ETH\n");

  // Deploy GasSponsor
  const GasSponsor = await hre.ethers.getContractFactory("GasSponsor");
  const gasSponsor = await GasSponsor.deploy();
  await gasSponsor.waitForDeployment();

  const contractAddress = await gasSponsor.getAddress();
  console.log("✅ GasSponsor deployed to:", contractAddress);
  console.log("\nNetwork:", hre.network.name);
  console.log("Chain ID:", (await hre.ethers.provider.getNetwork()).chainId.toString());

  // Fund the contract with some ETH for gas sponsorship
  const fundAmount = hre.ethers.parseEther("0.05"); // 0.05 ETH
  console.log("\nFunding contract with", hre.ethers.formatEther(fundAmount), "ETH...");
  
  const fundTx = await deployer.sendTransaction({
    to: contractAddress,
    value: fundAmount
  });
  await fundTx.wait();
  
  const contractBalance = await hre.ethers.provider.getBalance(contractAddress);
  console.log("Contract balance:", hre.ethers.formatEther(contractBalance), "ETH");

  console.log("\n" + "═".repeat(60));
  console.log("DEPLOYMENT COMPLETE");
  console.log("═".repeat(60));
  console.log("\nContract Address:", contractAddress);
  console.log("\nNext steps:");
  console.log("1. Add session keys: gasSponsor.addSigner(sessionKeyAddress)");
  console.log("2. Fund contract: send ETH to", contractAddress);
  console.log("3. Update demo/app.js with contract address");
  console.log("\nVerify on Etherscan:");
  console.log(`npx hardhat verify --network ${hre.network.name} ${contractAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
