import pkg from "hardhat";
import fs from "fs";
import path from "path";

const { ethers } = pkg;

async function main() {
  const [, attacker]    = await ethers.getSigners();
  const addrFile        = path.join(process.env.SHARED_DIR || ".", "contract_address.txt");
  const honeypotAddress = fs.existsSync(addrFile)
    ? fs.readFileSync(addrFile, "utf8").trim()
      : "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";

  console.log("=== Reentrancy Attack Simulation ===");
  console.log("Honeypot:", honeypotAddress);

  const AttackerFactory  = await ethers.getContractFactory("AttackerContract", attacker);
  const attackerContract = await AttackerFactory.deploy(honeypotAddress);
  await attackerContract.waitForDeployment();
  console.log("AttackerContract:", await attackerContract.getAddress());

  const before = await ethers.provider.getBalance(honeypotAddress);
  console.log("Honeypot balance before:", ethers.formatEther(before), "ETH");

  const tx = await attackerContract.connect(attacker).attack({ value: ethers.parseEther("0.5") });
  await tx.wait();

  const after = await ethers.provider.getBalance(honeypotAddress);
  console.log("Honeypot balance after :", ethers.formatEther(after), "ETH");
  console.log("Reentry count         :", (await attackerContract.attackCount()).toString());
  console.log("\nDone. Watch the AI agent terminal for reports.");
}

main().catch((err) => { console.error(err); process.exit(1); });