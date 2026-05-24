#!/usr/bin/env python3
"""
Etherscan'dan BENIGN bytecode çeker; malicious için gerçekçi sentetik üretir.
Kullanım: python fetch_dataset.py --key ETHERSCAN_API_KEY
"""
import sys, time, csv, argparse, random
import requests

random.seed(42)
API = "https://api.etherscan.io/api"

BENIGN = [
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC"),
    ("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI"),
    ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT"),
    ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC"),
    ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "UniV2Router"),
    ("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "UniV2Factory"),
    ("0x1F98431c8aD98523631AE4a59f267346ea31F984", "UniV3Factory"),
    ("0x514910771AF9Ca656af840dff83E8264EcF986CA", "LINK"),
    ("0xD533a949740bb3306d119CC777fa900bA034cd52", "CRV"),
    ("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", "MKR"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "UNI"),
    ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", "AAVE"),
    ("0xc00e94Cb662C3520282E6f5717214004A7f26888", "COMP"),
    ("0xba100000625a3754423978a60c9317c58a424e3D", "BAL"),
]

PATTERNS = {
    "REENTRANCY": (
        "6080604052"
        + "600054"
        + "f1" * 8
        + "600055" * 4
        + "f1f2" * 3
        + "00"
    ),
    "SELFDESTRUCT": (
        "6080604052"
        + "ff" * 12
        + "6000ff" * 4
        + "00"
    ),
    "DELEGATECALL_ABUSE": (
        "6080604052"
        + "f4" * 20
        + "600060006000600060006000f4" * 3
        + "00"
    ),
    "FACTORY_ATTACK": (
        "6080604052"
        + "f0" * 6
        + "f5" * 6
        + "600060006000f0" * 3
        + "6000600060006000f5" * 3
        + "00"
    ),
    "STORAGE_MANIP": (
        "6080604052"
        + "55" * 15
        + "".join(f"60{i:02x}60{i:02x}55" for i in range(8))
        + "00"
    ),
    "OBFUSCATED": (
        "6080604052"
        + "57" * 10
        + "56" * 10
        + "5b" * 8
        + "6001576001565b" * 5
        + "00"
    ),
}


def fetch_code(addr, key):
    r = requests.get(API, params={
        "module": "proxy", "action": "eth_getCode",
        "address": addr, "tag": "latest", "apikey": key,
    }, timeout=10)
    code = r.json().get("result", "0x")
    return code if code and code != "0x" and len(code) > 4 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", default="mini_dataset.csv")
    ap.add_argument("--per-class", type=int, default=20)
    args = ap.parse_args()

    rows = []

    print(f"[*] Etherscan'dan {len(BENIGN)} BENIGN adres cekiliyor...")
    for addr, desc in BENIGN:
        try:
            code = fetch_code(addr, args.key)
            if code:
                rows.append({"bytecode": code, "label": 0,
                             "attack_type": "BENIGN", "description": desc})
                print(f"  OK  {desc}  ({len(code)//2} bytes)")
            else:
                print(f"  --  {desc}  (bos)")
        except Exception as e:
            print(f"  ERR {desc}: {e}")
        time.sleep(0.25)
        
    benign_count = sum(1 for r in rows if r["attack_type"] == "BENIGN")
    print(f"[+] {benign_count} BENIGN ornek toplandi")
    if benign_count < 10:
        print("[*] BENIGN fallback: 20 sentetik ornek ekleniyor...")
        benign_patterns = [
            "6080604052348015610010576000fd5b50",
            "608060405234801561001057600080fd5b50610150806100206000396000f3fe",
            "6080604052600436106100295760003560e01c8063d0e30db014610034575b600080fd",
            "60806040526004361061004157600035f3fe6080604052600436106100",
        ]
        for i in range(20):
            base = benign_patterns[i % len(benign_patterns)]
            noise = "".join(f"{random.randint(0, 255):02x}" for _ in range(random.randint(4, 12)))
            rows.append({"bytecode": "0x" + base + noise, "label": 0,
                         "attack_type": "BENIGN", "description": f"BENIGN_synthetic_{i}"})

    label = 1
    for attack_type, pattern in PATTERNS.items():
        print(f"[*] {attack_type}: {args.per_class} ornek uretiliyor...")
        for i in range(args.per_class):
            noise = "".join(f"{random.randint(0, 255):02x}" for _ in range(random.randint(4, 16)))
            code = "0x" + pattern + noise
            rows.append({"bytecode": code, "label": label,
                         "attack_type": attack_type,
                         "description": f"{attack_type}_synthetic_{i}"})
        label += 1

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bytecode", "label", "attack_type", "description"])
        w.writeheader()
        w.writerows(rows)

    from collections import Counter
    counts = Counter(r["attack_type"] for r in rows)
    print(f"\n[+] {args.out} yazildi — {len(rows)} ornek")
    for k, v in counts.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()