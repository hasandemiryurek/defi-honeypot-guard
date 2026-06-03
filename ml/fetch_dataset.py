#!/usr/bin/env python3
"""
BENIGN  : Uniswap/Compound token listesinden (GitHub raw) → Etherscan bytecode
MALICIOUS: DeFiHackLabs sol dosyaları + Forta labelled-datasets → Etherscan bytecode

"""
import time, csv, argparse, re, json, subprocess, shutil, sys
import urllib.parse
from collections import defaultdict

ETHERSCAN_API = "https://api.etherscan.io/v2/api"

LABEL_MAP = {
    "BENIGN":             0,
    "REENTRANCY":         1,
    "SELFDESTRUCT":       2,
    "DELEGATECALL_ABUSE": 3,
    "FACTORY_ATTACK":     4,
    "STORAGE_MANIP":      5,
    "OBFUSCATED":         6,
}

KEYWORD_MAP = [
    ("REENTRANCY",         ["reentrancy", "re-entrancy", "reentrant"]),
    ("SELFDESTRUCT",       ["selfdestruct", "self-destruct"]),
    ("DELEGATECALL_ABUSE", ["delegatecall", "delegate", "proxy"]),
    ("FACTORY_ATTACK",     ["factory", "create2", "clone"]),
    ("STORAGE_MANIP",      ["storage", "accesscontrol", "access_control", "privilege"]),
    ("OBFUSCATED",         ["flashloan", "flash_loan", "oracle",
                            "pricemanipulation", "price_manipulation"]),
]

_CURL = "curl.exe" if sys.platform == "win32" else (shutil.which("curl") or "curl")


def _get(url, params=None):
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    result = subprocess.run(
        [_CURL, "-s", "-k", "--noproxy", "*", "--max-time", "60",
         "-H", "User-Agent: Mozilla/5.0", url],
        capture_output=True,
    )
    if result.returncode != 0:
        raise Exception(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout.decode("utf-8", errors="replace")


def _get_json(url, params=None):
    return json.loads(_get(url, params))


def fetch_benign_contracts(limit=300):
    sources = [
        "https://raw.githubusercontent.com/Uniswap/default-token-list/main/src/tokens/mainnet.json",
        "https://raw.githubusercontent.com/compound-finance/token-list/master/compound.tokenlist.json",
    ]
    contracts = []
    seen = set()
    for url in sources:
        print(f"[*] Fetching token list: {url.split('/')[-1]}")
        try:
            data = _get_json(url)
            tokens = data if isinstance(data, list) else data.get("tokens", [])
            for t in tokens:
                if t.get("chainId", 0) != 1:
                    continue
                addr = t.get("address", "")
                if addr and len(addr) == 42 and addr.lower() not in seen:
                    contracts.append((addr, t.get("symbol", "?").upper()))
                    seen.add(addr.lower())
        except Exception as e:
            print(f"  ERR {url}: {e}")
    print(f"  >> {len(contracts)} BENIGN contracts found, first {limit} will be fetched")
    return contracts[:limit]


def load_benign_from_csv(path):
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("attack_type") == "BENIGN":
                    rows.append(row)
        print(f"[*] {path} dosyasindan {len(rows)} BENIGN row is loaded")
    except Exception as e:
        print(f"  ERR CSV load: {e}")
    return rows


def classify_attack(text: str):
    t = text.lower()
    for label, keywords in KEYWORD_MAP:
        if any(kw in t for kw in keywords):
            return label
    return None


def fetch_defihacklabs_sol_files(max_files=691):
    print("[*] DeFiHackLabs dosya listesi aliniyor (GitHub API)...")
    try:
        data = _get_json(
            "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/git/trees/main",
            {"recursive": "1"},
        )
    except Exception as e:
        print(f"  ERR GitHub API: {e}")
        return []
    files = [
        item["path"] for item in data.get("tree", [])
        if "test" in item.get("path", "") and item["path"].endswith("_exp.sol")
    ]
    print(f"  >> {len(files)} exploit dosyasi bulundu, ilk {max_files} taranacak")
    return files[:max_files]


def extract_attacker_addresses(content: str):
    addr_re = re.compile(
        r'(?:attacker|exploiter|hacker|exploit(?:er|_contract)?|attack(?:_contract)?'
        r'|victim|vulnerable|target|pool|vault|lending|protocol'
        r'|ATTACKER|EXPLOITER|HACKER|VICTIM|TARGET)'
        r'[^;=\n]{0,60}?(0x[0-9a-fA-F]{40})',
        re.IGNORECASE,
    )
    found = []
    for m in addr_re.finditer(content):
        addr = m.group(1)
        if addr not in found:
            found.append(addr)
    return found


def fetch_malicious_from_github(max_files=691):
    sol_files = fetch_defihacklabs_sol_files(max_files)
    if not sol_files:
        return defaultdict(list)
    results = defaultdict(list)
    seen = set()
    base = "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/"
    for i, path in enumerate(sol_files, 1):
        try:
            content = _get(base + path)
        except Exception:
            continue
        filename = path.split("/")[-1]
        attack_type = classify_attack(filename + " " + content[:2000])
        if not attack_type:
            continue
        for addr in extract_attacker_addresses(content):
            if addr.lower() not in seen:
                results[attack_type].append((addr, f"DeFiHackLabs_{filename[:40]}"))
                seen.add(addr.lower())
        if i % 20 == 0:
            print(f"  .. {i}/{len(sol_files)} file scanned, "
                  f"{sum(len(v) for v in results.values())} addresses found")
        time.sleep(0.05)
    print(f"  >> Total {sum(len(v) for v in results.values())} addresses (DeFiHackLabs):")
    for k, v in results.items():
        print(f"     {k}: {len(v)}")
    return results


def fetch_forta_malicious():
    url = "https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/malicious_smart_contracts.csv"
    print("[*] Forta labelled-datasets is fetching")
    try:
        content = _get(url)
    except Exception as e:
        print(f"  ERR Forta: {e}")
        return defaultdict(list)
    results = defaultdict(list)
    seen = set()
    for line in content.strip().split("\n")[1:]:
        parts = line.split(",")
        if len(parts) < 2:
            continue
        addr  = parts[0].strip()
        tag   = parts[1].strip().lower()
        notes = parts[6].strip().lower() if len(parts) > 6 else ""
        if not addr.startswith("0x") or len(addr) != 42 or addr.lower() in seen:
            continue
        attack_type = classify_attack(tag + " " + notes)
        if not attack_type:
            if any(kw in tag + notes for kw in ["exploit", "heist", "hack", "phish"]):
                attack_type = "OBFUSCATED"
            else:
                continue
        results[attack_type].append((addr, f"Forta_{tag[:30]}"))
        seen.add(addr.lower())
    print(f"  >> {sum(len(v) for v in results.values())} adres parse edildi (Forta):")
    for k, v in results.items():
        print(f"     {k}: {len(v)}")
    return results


def fetch_code(addr: str, key: str):
    try:
        data = _get_json(ETHERSCAN_API, {
            "chainid": "1", "module": "proxy", "action": "eth_getCode",
            "address": addr, "tag": "latest", "apikey": key,
        })
        code = data.get("result", "0x")
        if not code or not code.startswith("0x") or len(code) < 10:
            return None
        if not re.match(r'^0x[0-9a-fA-F]+$', code):
            return None
        return code
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", default="ml/mini_dataset.csv")
    ap.add_argument("--benign-limit", type=int, default=300)
    ap.add_argument("--sol-limit",    type=int, default=691)
    ap.add_argument("--skip-benign",  action="store_true")
    ap.add_argument("--load-benign",  default=None)
    args = ap.parse_args()

    rows = []

    if args.skip_benign and args.load_benign:
        rows = load_benign_from_csv(args.load_benign)
    else:
        cg_contracts = fetch_benign_contracts(args.benign_limit)
        print(f"\n[*] {len(cg_contracts)} BENIGN adres Etherscan'dan cekiliyor...")
        for i, (addr, symbol) in enumerate(cg_contracts, 1):
            code = fetch_code(addr, args.key)
            if code:
                rows.append({"bytecode": code, "label": 0,
                             "attack_type": "BENIGN", "description": symbol})
                print(f"  OK  [{i:3d}] {symbol:<12} {addr}")
            else:
                print(f"  --  [{i:3d}] {symbol:<12} (bos/EOA)")
            time.sleep(0.22)

    print(f"\n[+] {sum(1 for r in rows if r['attack_type']=='BENIGN')} BENIGN samples ready, now fetching MALICIOUS samples")

    print()
    malicious_map = fetch_malicious_from_github(args.sol_limit)
    forta_map = fetch_forta_malicious()
    for k, v in forta_map.items():
        existing = {a.lower() for a, _ in malicious_map[k]}
        for addr, desc in v:
            if addr.lower() not in existing:
                malicious_map[k].append((addr, desc))

    print(f"\n[*] malicious addressess fetching from Etherscan using API key")
    for attack_type, addresses in malicious_map.items():
        label = LABEL_MAP.get(attack_type, 0)
        found = 0
        for addr, desc in addresses:
            code = fetch_code(addr, args.key)
            if code:
                rows.append({"bytecode": code, "label": label,
                             "attack_type": attack_type, "description": desc})
                print(f"  OK  {attack_type:<20} {addr}")
                found += 1
            else:
                print(f"  --  {attack_type:<20} {addr} (bos/selfdestruct)")
            time.sleep(0.22)
        print(f"  >> {attack_type}: {found}/{len(addresses)} bytecode found")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bytecode", "label", "attack_type", "description"])
        w.writeheader()
        w.writerows(rows)

    from collections import Counter
    counts = Counter(r["attack_type"] for r in rows)
    print(f"\n[+] {args.out} yazildi — {len(rows)} real samples:")
    for k in ["BENIGN"] + [k for k in LABEL_MAP if k != "BENIGN"]:
        print(f"    {k:<20}: {counts.get(k, 0)}")


if __name__ == "__main__":
    main()