import pkg from "hardhat";
import fs from "fs";
import path from "path";

const { ethers } = pkg;

async function loadHoneypot(ethers) {
  const addrFile = path.join(process.env.SHARED_DIR || ".", "contract_address.txt");
  const address  = fs.existsSync(addrFile)
    ? fs.readFileSync(addrFile, "utf8").trim()
      : "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
  const artifact = JSON.parse(
    fs.readFileSync("artifacts/contracts/HoneypotAdvanced.sol/HoneypotAdvanced.json", "utf8")
  );
  return new ethers.Contract(address, artifact.abi, (await ethers.getSigners())[1]);
}

async function main() {
  const [, attacker] = await ethers.getSigners();
  const honeypot     = await loadHoneypot(ethers);
  console.log("=== Simple Attack Simulation ===");
  console.log("Attacker:", attacker.address);

  // T5: direct ETH
  const tx1 = await attacker.sendTransaction({ to: await honeypot.getAddress(), value: ethers.parseEther("0.5") });
  await tx1.wait(); console.log("[T5] DIRECT_ETH_TRANSFER sent");

  // T3: overflow bait
  const tx2 = await honeypot.connect(attacker).claimBonus(999);
  await tx2.wait(); console.log("[T3] OVERFLOW_ATTEMPT sent");

  // ownership grab
  const tx3 = await honeypot.connect(attacker).transferOwnership(attacker.address);
  await tx3.wait(); console.log("[T5] OWNERSHIP_GRAB sent");

  // T4: timestamp manip
  const tx4 = await honeypot.connect(attacker).luckyDraw({ value: ethers.parseEther("0.01") });
  await tx4.wait(); console.log("[T4] LUCKY_DRAW sent");

  console.log("\nDone. Watch the AI agent terminal for reports.");
}

main().catch((err) => { console.error(err); process.exit(1); });