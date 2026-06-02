#!/usr/bin/env python3
import json, csv
from pathlib import Path
from collections import Counter

ARTIFACT_MAP = [
    ("AttackerContract",     "REENTRANCY"),
    ("AttackerDelegatecall", "DELEGATECALL_ABUSE"),
    ("AttackerFactory",      "FACTORY_ATTACK"),
    ("MiniContract",         "FACTORY_ATTACK"),
    ("AttackerStorageManip", "STORAGE_MANIP"),
    ("AttackerObfuscated",   "OBFUSCATED"),
]

LABEL_ORDER = ["BENIGN","REENTRANCY","SELFDESTRUCT","DELEGATECALL_ABUSE",
               "FACTORY_ATTACK","STORAGE_MANIP","OBFUSCATED"]

DATASET  = Path("ml/mini_dataset.csv")
ARTIFACTS = Path("artifacts/contracts")

def load_existing():
    rows, seen = [], set()
    with open(DATASET, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
            seen.add(row["bytecode"][:40])
    return rows, seen

def find_artifact(name):
    for p in ARTIFACTS.rglob(f"{name}.json"):
        if ".dbg." not in p.name:
            return p
    return None

def main():
    if not ARTIFACTS.exists():
        print("HATA: artifacts/ klasoru bulunamadi. Once 'npx hardhat compile' calistir.")
        return
    rows, seen = load_existing()
    added = 0
    for contract_name, attack_type in ARTIFACT_MAP:
        path = find_artifact(contract_name)
        if not path:
            print(f"  -- {contract_name}: artifact bulunamadi"); continue
        data = json.loads(path.read_text())
        bytecode = data.get("bytecode", "")
        if not bytecode or bytecode == "0x" or len(bytecode) < 20:
            print(f"  -- {contract_name}: bytecode bos"); continue
        key = bytecode[:40]
        if key in seen:
            print(f"  ~~ {contract_name}: zaten mevcut"); continue
        label = LABEL_ORDER.index(attack_type) if attack_type in LABEL_ORDER else 0
        rows.append({"bytecode": bytecode, "label": label,
                     "attack_type": attack_type, "description": f"Local_{contract_name}"})
        seen.add(key); added += 1
        print(f"  OK {contract_name:30s} -> {attack_type}")
    with open(DATASET, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bytecode","label","attack_type","description"])
        w.writeheader(); w.writerows(rows)
    counts = Counter(r["attack_type"] for r in rows)
    print(f"\n[+] {added} yeni ornek eklendi. Toplam: {len(rows)}")
    for k in LABEL_ORDER:
        if counts.get(k, 0) > 0:
            print(f"    {k:<20}: {counts[k]}")

if __name__ == "__main__":
    main()