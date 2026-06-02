import pkg from "hardhat";
const { ethers } = pkg;
import { readFileSync } from "fs";

async function main() {
  const address = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const [owner] = await ethers.getSigners();
  const contract = await ethers.getContractAt("HoneypotAdvanced", address);
  const tx = await contract.unpause();
  await tx.wait();
  console.log("Kontrat aktif edildi");
}

main().catch(console.error);