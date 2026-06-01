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

# DVDFi kaynak kodlarından türetilen gerçekçi EVM opcode pattern'leri.
# Her biri bir DVDFi challenge'ına karşılık gelir.
PATTERNS = {
    # DVDFi: side-entrance — CALL external SSTORE'dan önce geliyor
    "REENTRANCY": (
        "6080604052"
        "60003560e01c"
        "63d2134b731461100057"
        "60003560e01c"
        "633ccfd60b1461200057"
        "60003560e01c"
        "63fc0e3d421461400057"
        "6000fd"
        "30315261"
        "5a6000808080"
        "6000f1"
        "610000546000016100005561"
        "303151106100005761"
    ),
    # DVDFi: unstoppable — selfdestruct ile ERC4626 totalAssets invariant kırma
    "SELFDESTRUCT": (
        "6080604052"
        "60003560e01c"
        "6318160ddd1461100057"
        "60003560e01c"
        "6301e3a1f41461300057"
        "6000fd"
        "6318160ddd"
        "fa51"
        "6301e3a1f4"
        "fa51"
        "8114156100005761"
        "ff"
        "6000ff"
    ),
    # DVDFi: truster — flashLoan içinde saldırgan kontrollü target.call(data)
    "DELEGATECALL_ABUSE": (
        "6080604052"
        "60003560e01c"
        "631cff79cd1461100057"
        "6000fd"
        "35600401"
        "35602401"
        "35604401"
        "63a9059cbb"
        "f1"
        "36606403"
        "6064"
        "35"
        "5af1"
        "6370a08231"
        "fa"
        "51106100005761"
    ),
    # DVDFi: climber — timelock execute() önce çalışıyor, isReady() sonra kontrol
    "FACTORY_ATTACK": (
        "6080604052"
        "60003560e01c"
        "630825f38f1461100057"
        "60003560e01c"
        "63b1c5f4271461300057"
        "6000fd"
        "35600401"
        "8051"
        "6000"
        "5b"
        "5a6000"
        "f4"
        "600101818161105761"
        "63584b9f56"
        "fa"
        "156100005761"
    ),
    # DVDFi: puppet — UniswapV1 spot price oracle manipülasyonu
    "STORAGE_MANIP": (
        "6080604052"
        "60003560e01c"
        "634b8a35291461100057"
        "60003560e01c"
        "63e71bef881461300057"
        "6000fd"
        "6398995f81"
        "fa51"
        "6100020252"
        "6323b872dd"
        "f1"
        "63a9059cbb"
        "f1"
    ),
    # DVDFi: selfie — flash loan ile governance token manipülasyonu
    "FLASH_LOAN": (
        "6080604052"
        "60003560e01c"
        "635cffe9be1461100057"
        "60003560e01c"
        "63aaf5eb681461300057"
        "6000fd"
        "600154600114"
        "156100005761"
        "6002600055"
        "4752"
        "63a9059cbb"
        "f1"
        "6338d52a2c"
        "f1"
        "6323b872dd"
        "fa"
        "4751116100005761"
        "6001600055"
    ),
    # DVDFi: abi-smuggling — calldata offset manipülasyonu ile izin bypass
    "OBFUSCATED": (
        "6080604052"
        "60003560e01c"
        "631cff79cd1461100057"
        "6000fd"
        "35600401"
        "35602401"
        "60643563"
        "6335f4a7b3"
        "14"
        "156100005761"
        "5af4"
    ),
    # DVDFi: free-rider — NFT transferden sonra owner değişiyor, msg.value reuse
    "LOGIC_BUG": (
        "6080604052"
        "60003560e01c"
        "6347c79fdd1461100057"
        "60003560e01c"
        "638a72ea641461300057"
        "6000fd"
        "5b"
        "35600401"
        "6000"
        "5b"
        "5134106100005761"
        "6342842e0e"
        "f1"
        "636352211e"
        "fa51"
        "5a60008080"
        "f1"
        "6001018181611057"
    ),
    # DVDFi: naive-receiver — multicall delegatecall ile msg.value reuse
    "ARBITRARY_CALL": (
        "6080604052"
        "60003560e01c"
        "63ac9650d81461100057"
        "6000fd"
        "35600401"
        "8051"
        "6000"
        "5b"
        "5af4"
        "6001018181611057"
        "6301ffc9a7"
        "f1"
        "5134116100005761"
    ),
}


def fetch_code(addr, key):
    r = requests.get("https://api.etherscan.io/v2/api", params={
        "chainid": "1",
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