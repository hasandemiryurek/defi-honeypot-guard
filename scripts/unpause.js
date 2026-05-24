import pkg from "hardhat";
const { ethers } = pkg;
import { readFileSync } from "fs";

async function main() {
  const address = readFileSync("/shared/contract_address.txt", "utf8").trim();
  const [owner] = await ethers.getSigners();
  const contract = await ethers.getContractAt("HoneypotAdvanced", address);
  const tx = await contract.unpause();
  await tx.wait();
  console.log("Kontrat aktif edildi");
}

main().catch(console.error);