import pkg from "hardhat";
import fs from "fs";
import path from "path";

const { ethers } = pkg;

function getHoneypotAddress() {
  const addrFile = path.join(process.env.SHARED_DIR || ".", "contract_address.txt");
  return fs.existsSync(addrFile)
    ? fs.readFileSync(addrFile, "utf8").trim()
      : "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
}

async function deployAndAttack(contractName, attackerSigner, honeypotAddr, attackFn) {
  console.log(`\n--- [${contractName}] ---`);
  const factory  = await ethers.getContractFactory(contractName, attackerSigner);
  const instance = await factory.deploy(honeypotAddr);
  await instance.waitForDeployment();
  console.log(`Deployed: ${await instance.getAddress()}`);
  try {
    await attackFn(instance);
    console.log(`Done — AI agent should classify as: ${contractName.replace("Attacker", "")}`);
  } catch (e) {
    console.log(`Reverted: ${e.message?.slice(0, 80)}`);
  }
}

async function main() {
  const [owner, attacker] = await ethers.getSigners();
  const honeypotAddr = await getHoneypotAddress();

  const artifact = JSON.parse(fs.readFileSync(
    "artifacts/contracts/HoneypotAdvanced.sol/HoneypotAdvanced.json", "utf8"
  ));
  const honeypotContract = new ethers.Contract(honeypotAddr, artifact.abi, owner);

  console.log("=== ML Demo Attack Suite ===");
  console.log("Honeypot :", honeypotAddr);
  console.log("Attacker :", attacker.address);

  // 1. REENTRANCY
  try { await (await honeypotContract.unpause()).wait(); } catch {}
  await deployAndAttack("AttackerContract", attacker, honeypotAddr, async (c) => {
    const tx = await c.attack({ value: ethers.parseEther("0.1") });
    await tx.wait();
  });

  // 2. DELEGATECALL_ABUSE
  try { await (await honeypotContract.unpause()).wait(); } catch {}
  await deployAndAttack("AttackerDelegatecall", attacker, honeypotAddr, async (c) => {
    const tx = await c.attack({ value: ethers.parseEther("0.1") });
    await tx.wait();
  });

  // 3. FACTORY_ATTACK
  try { await (await honeypotContract.unpause()).wait(); } catch {}
  await deployAndAttack("AttackerFactory", attacker, honeypotAddr, async (c) => {
    const tx = await c.attack({ value: ethers.parseEther("0.1") });
    await tx.wait();
    console.log("Children created:", (await c.childCount()).toString());
  });

  // 4. STORAGE_MANIP
  try { await (await honeypotContract.unpause()).wait(); } catch {}
  await deployAndAttack("AttackerStorageManip", attacker, honeypotAddr, async (c) => {
    const tx = await c.attack({ value: ethers.parseEther("0.01") });
    await tx.wait();
  });

  // 5. OBFUSCATED
  try { await (await honeypotContract.unpause()).wait(); } catch {}
  await deployAndAttack("AttackerObfuscated", attacker, honeypotAddr, async (c) => {
    const tx = await c.attack({ value: ethers.parseEther("0.01") });
    await tx.wait();
  });

  console.log("\n=== Tüm saldırılar tamamlandı. Agent terminalini kontrol et. ===");
}

main().catch((err) => { console.error(err); process.exit(1); });