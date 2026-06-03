#!/usr/bin/env python3
"""
Ucretsiz kaynaklardan bytecode ceker:
1. Uniswap V2 factory'den otomatik pair adresleri (FACTORY_ATTACK)
2. DeFi Llama API'den protokol adresleri (cesitli siniflar)
3. Bilinen sabit adresler

"""
import json, csv, time, subprocess, shutil, sys, urllib.parse, urllib.request
from pathlib import Path
from collections import Counter

_CURL = "curl.exe" if sys.platform == "win32" else (shutil.which("curl") or "curl")
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
OUT = Path("ml/mini_dataset.csv")

LABEL_MAP = {
    "BENIGN": 0, "REENTRANCY": 1, "SELFDESTRUCT": 2,
    "DELEGATECALL_ABUSE": 3, "FACTORY_ATTACK": 4,
    "STORAGE_MANIP": 5, "OBFUSCATED": 6,
}


REENTRANCY_CONTRACTS = [
    ("0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd", "SushiMasterChefV1"),
    ("0xEF0881eC094552b2e128Cf945EF17a6752B4Ec5d", "SushiMasterChefV2"),
    ("0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "Curve3pool"),
    ("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022", "CurveStETH"),
    ("0xA5407eAE9Ba41422680e2e00537571bcC53efBfD", "CurveSUSD"),
    ("0x45F783CCE6B7FF23B2ab2D70e416cdb7D6055f51", "CurveYpool"),
    ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "UniV2Router"),
    ("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", "SushiRouter"),
    ("0xBA12222222228d8Ba445958a75a0704d566BF2C8", "BalancerVault"),
    ("0xF403C135812408BFbE8713b5A23a04b3D48AAE31", "ConvexBooster"),
    ("0x72a19342e8F1838460eBFCCEf09F6585e32db86E", "ConvexCVX"),
    ("0x5f18C75AbDAe578b483E5F43f12a39cF75b973a9", "YearnUSDC"),
    ("0xE592427A0AEce92De3Edee1F18E0157C05861564", "UniV3Router"),
    ("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "UniV3Router2"),
    ("0xDef1C0ded9bec7F1a1670819833240f027b25EfF", "ZeroExExchange"),
    ("0x1111111254EEB25477B68fb85Ed929f73A960582", "1inchV5"),
    ("0x1111111254fb6c44bAC0beD2854e76F90643097d", "1inchV4"),
    ("0x6131B5fae19EA4f9D964eAc0408E4408b66337b5", "KyberSwap"),
    ("0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", "UniUniversalRouter"),
    ("0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", "UniUniversalRouterOld"),
    # Aave lending (CALL+SSTORE yogun)
    ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "AaveLendingPoolV2"),
    ("0x398eC7346DcD622eDc5ae82352F02bE94C62d119", "AaveLendingPoolV1"),
    ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "AaveLendingPoolV3"),
    ("0x794a61358D6845594F94dc1DB02A252b5b4814aD", "AavePoolV3"),
    ("0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf", "AavePolygon"),
    # Compound v2 markets
    ("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "CompoundComptrollerV2"),
    ("0xf859A1AD94BcF445A406B892eF0d3082f4174088", "CompoundGovernor"),
    # Yearn vaults (CALL+SSTORE)
    ("0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e", "YearnYFI"),
    ("0x19D3364A399d251E894aC732651be8B0E4e85001", "YearnDAI"),
    ("0xa9fE4601811213c340e850ea305481afF02f5b28", "YearnWETH"),
    ("0xdA816459F1AB5631232FE5e97a05BBBb94970c95", "YearnDAIv2"),
    ("0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE", "YearnUSDCv2"),
    # Liquity
    ("0xA39739EF8b0231DbFA0DcdA07d7e29faAbCf4bb2", "LiquityTroveManager"),
    ("0x24179CD81c9e782A4096035f7eC97fB8B783e007", "LiquityBorrowerOps"),
    # MakerDAO
    ("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", "MakerMKR"),
    ("0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B", "MakerVat"),
    ("0xA950524441892A31ebddF91d3cEEFa04Bf454466", "MakerDog"),
    # Uniswap V3 pools (farkli bytecode'lar)
    ("0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8", "UniV3_ETH_USDC_3000"),
    ("0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36", "UniV3_ETH_USDT_3000"),
    ("0xcbCdF9626bC03E24f779434178A73a0B4bad62eD", "UniV3_WBTC_ETH_3000"),
    ("0x6c6Bc977E13Df9b0de53b251522280BB72383700", "UniV3_DAI_USDC_500"),
    ("0x5764f18d1a3c9Fc2Ee3d5e82A96CF3c1C649F6E", "UniV3_USDC_USDT_500"),
    # Lido staking
    ("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "LidoStETH"),
    ("0x47EbaB13B806773ec2A2d16873e2dF770D130b50", "LidoNodeOps"),
    # Curve gauges (SSTORE yogun)
    ("0x7ca5b0a2910B33e9759DC7dDB0413949071D7575", "CurveGauge3pool"),
    ("0x182B723a58739a9c974cFDB385ceaDb237453c28", "CurveGaugeSTETH"),
    ("0xF98450B5602fa59CC66e1379DFfB6FDDc724CfA4", "CurveGaugeSUSD"),
    # Synthetix
    ("0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F", "SynthetixSNX"),
    ("0xb671F2210B1F6621A2607EA63E6B21D094E161d4", "SynthetixRewards"),
    ("0xDC01020857afbaE65224CfCFd4bf6d4ED5d96F96", "SynthetixFeePool"),
]

DELEGATECALL_CONTRACTS = [
    ("0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643", "cDAI"),
    ("0x39AA39c021dfbaE8faC545936693aC917d5E7563", "cUSDC"),
    ("0xf650C3d88D12dB855b8bf7D11Be6C55A4e07dCC9", "cUSDT"),
    ("0xC11b1268C1A384e55C48022e9d1cFc1b8B3dA25F", "cWBTC"),
    ("0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5", "cETH"),
    ("0x6C8c6b02E7b2BE14d4fA6022Dfd6d75921D90E4E", "cBAT"),
    ("0x158079Ee67Fce2f58472A96584A73C7Ab9AC95c1", "cREP"),
    ("0xB3319f5D18Bc0D84dD1b4825Dcde5d5f7266d407", "cZRX"),
    ("0x35A18000230DA775CAc24873d00Ff85BccdeD550", "cUNI"),
    ("0x4Fabb145d64652a948d72533023f6E7A623C7C53", "BUSD_proxy"),
    ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC_proxy"),
    ("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI_proxy"),
    ("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "CompoundComptroller"),
    ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", "AAVE_proxy"),
    ("0xD533a949740bb3306d119CC777fa900bA034cd52", "CRV_proxy"),
]

STORAGE_CONTRACTS = [
    ("0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "CryptoKitties"),
    ("0x7f268357A8c2552623316e2562D90e642bB538E5", "OpenSeaWyvernV2"),
    ("0x7Be8076f4EA4A4AD08075C2508e481d6C946D12b", "OpenSeaWyvernV1"),
    ("0x00000000006c3852cbEf3e08E8dF289169EdE581", "Seaport"),
    ("0x59728544B08AB483533076417FbBB2fD0B17CE3a", "LooksRare"),
    ("0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", "CryptoPunks"),
    ("0x60F80121C31A0d46B5279700f9DF786054aa5eE5", "Rarible"),
    ("0x2b2e8cda09bba9660dca5cb6233787738ad68329", "SuperRare"),
    ("0x41A322b28D0fF354040e2CbC676F0320d8c8850d", "SuperFarm"),
    ("0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac", "SushiV2Factory"),
    # ERC721/NFT (mapping yogun SSTORE)
    ("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", "BAYC"),
    ("0x60E4d786628Fea6478F785A6d7e704777c86a7c6", "MAYC"),
    ("0x34d85c9CDeB23FA97cb08333b511ac86E1C4E258", "Otherdeed"),
    ("0x49cF6f5d44E70224e2E23fDcdd2C053F30aDA28B", "CloneX"),
    ("0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e", "Doodles"),
    ("0x23581767a106ae21c074b2276D25e5C3e136a68b", "Moonbirds"),
    ("0xED5AF388653567Af2F388E6224dC7C4b3241C544", "Azuki"),
    ("0x026224A2940bFE258D0dbE947919B62fE321F042", "Beanz"),
    # Governance/DAO (complex state machine)
    ("0x408ED6354d4973f66138C91495F2f2FCbd8724C3", "CompoundGovernorBravo"),
    ("0xEC568fffba86c094cf06b22134B23074DFE2252c", "ENSGovernor"),
    ("0x5e4be8Bc9637f0EAA1A755019e06A68ce081D58F", "AaveGovernanceV2"),
    ("0xEC568fffba86c094cf06b22134B23074DFE2252c", "UniswapGovernor"),
    # ENS registry
    ("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e", "ENSRegistry"),
    ("0x253553366Da8546fC250F225fe3d25d0C782303b", "ENSPublicResolver"),
    # Staking/rewards (SSTORE heavy)
    ("0xa1d0E215a23d7030842FC67cE582a6aFa3CCaB83", "YFIStaking"),
    ("0xDCB6A51eA3CA5d3Fd898Fd6564757c7aAeC3ca92", "CurveRewardGauge"),
    ("0x3Fe65692bfCD0e6CF84cB1E7d24108E434A7587e", "ConvexRewardPool"),
    ("0x0A760466E1B4621579a82a39CB56Dda2F4E70f03", "ConvexRewardPool2"),
    # Complex token contracts
    ("0x514910771AF9Ca656af840dff83E8264EcF986CA", "Chainlink_LINK"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "UNI_token"),
    ("0xc00e94Cb662C3520282E6f5717214004A7f26888", "COMP_token"),
    ("0xba100000625a3754423978a60c9317c58a424e3D", "BAL_token"),
]

FACTORY_CONTRACTS = [
    ("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "UniswapV2Factory"),
    ("0x1F98431c8aD98523631AE4a59f267346ea31F984", "UniswapV3Factory"),
    ("0x0000000000FFe8B47B3e2130213B802212439497", "CloneFactory_eip1167"),
    ("0x4e59b44847b379578588920cA78FbF26c0B4956C", "Create2Factory"),
    ("0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2", "GnosisSafeFactory"),
    ("0xce0042B868300000d44A59004Da54A005ffdcf9f", "SafeProxyFactory"),
    ("0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac", "SushiFactory"),
    ("0x1F98431c8aD98523631AE4a59f267346ea31F984", "UniV3Factory"),
    ("0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF", "Tornado01ETH"),
    ("0xA160cdAB225685dA1d56aa342Ad8841c3b53f291", "Tornado1ETH"),
    ("0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144", "Tornado10ETH"),
    ("0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF", "Tornado01"),
    ("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "TornadoRouter"),
]


def curl_get(url):
    result = subprocess.run(
        [_CURL, "-s", "-k", "--noproxy", "*", "--max-time", "30",
         "-H", "User-Agent: Mozilla/5.0", url],
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def fetch_code(address, api_key):
    params = urllib.parse.urlencode({
        "chainid": "1", "module": "proxy", "action": "eth_getCode",
        "address": address, "tag": "latest", "apikey": api_key,
    })
    raw = curl_get(ETHERSCAN_API + "?" + params)
    if not raw:
        return None
    try:
        code = json.loads(raw).get("result", "0x")
        if code and isinstance(code, str) and code.startswith("0x") and len(code) > 10:
            return code
    except Exception:
        pass
    return None


def eth_call(to, data, api_key):
    params = urllib.parse.urlencode({
        "chainid": "1", "module": "proxy", "action": "eth_call",
        "to": to, "data": data, "tag": "latest", "apikey": api_key,
    })
    raw = curl_get(ETHERSCAN_API + "?" + params)
    if not raw:
        return None
    try:
        return json.loads(raw).get("result", "0x")
    except Exception:
        return None


def get_uniswap_v2_pairs(api_key, count=20):
    """Uniswap V2 factory pair addressess."""
    factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    pairs = []
    print(f"[*] Uniswap V2'den {count} fetching pair addresses for factory attack samples")
    for i in range(count):
        data = "0x1e3dd18b" + hex(i)[2:].zfill(64)
        result = eth_call(factory, data, api_key)
        if result and len(result) >= 66:
            addr = "0x" + result[-40:]
            if addr != "0x" + "0" * 40:
                pairs.append(addr)
        time.sleep(0.22)
        if (i + 1) % 20 == 0:
            print(f"  .. {i+1}/{count} queries completed, {len(pairs)} pairs found")
    print(f"  >> {len(pairs)} Uniswap V2 pair addresses fetched")
    return pairs


def get_defillama_contracts():
    """DeFi Llama'dan addresses"""
    print("[*] DeFi Llama protocol addresses fetching...")
    raw = curl_get("https://api.llama.fi/protocols")
    if not raw:
        print("  cannot access DeFi Llama API")
        return []
    try:
        protocols = json.loads(raw)
        addrs = []
        for p in protocols:
            addr = p.get("address", "")
            if addr and addr.startswith("0x") and len(addr) == 42:
                addrs.append(addr)
        print(f"  >> {len(addrs)} protocol addresses found")
        return addrs[:60]
    except Exception as e:
        print(f"  ERR parse: {e}")
        return []
    
def get_coingecko_tokens(limit=120):
    """CoinGecko'dan Ethereum ERC20 token adresses fetching"""
    print(f"[*] fetching (aim: {limit})...")
    raw = curl_get("https://api.coingecko.com/api/v3/coins/list?include_platform=true")
    if not raw:
        print("  cannot access CoinGecko API")
        return []
    try:
        coins = json.loads(raw)
        addrs = []
        for coin in coins:
            platforms = coin.get("platforms", {})
            addr = platforms.get("ethereum", "")
            if addr and addr.startswith("0x") and len(addr) == 42:
                addrs.append(addr)
            if len(addrs) >= limit:
                break
        print(f"  >> {len(addrs)} ERC20 token adresi bulundu")
        return addrs
    except Exception as e:
        print(f"  ERR parse: {e}")
        return []


def process_addresses(addresses, attack_type, desc_prefix, api_key, seen, new_rows):
    label = LABEL_MAP.get(attack_type, 0)
    found = 0
    for i, item in enumerate(addresses):
        addr, desc = (item if isinstance(item, tuple) else (item, f"{desc_prefix}_{i}"))
        code = fetch_code(addr, api_key)
        if not code:
            print(f"  --  {attack_type:<20} {addr} (bos)")
        elif code[:40] in seen:
            print(f"  ~~  {attack_type:<20} {addr} (zaten var)")
        else:
            new_rows.append({"bytecode": code, "label": label,
                             "attack_type": attack_type, "description": desc})
            seen.add(code[:40])
            found += 1
            print(f"  OK  {attack_type:<20} {addr}")
        time.sleep(0.22)
    print(f"  >> {attack_type}: {found}/{len(addresses)} eklendi\n")
    return found


def main():
    api_key = sys.argv[1] if len(sys.argv) > 1 else input("Etherscan API key: ").strip()

    existing, seen = [], set()
    if OUT.exists():
        with open(OUT, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                existing.append(row)
                seen.add(row["bytecode"][:40])
    print(f"[*] Mevcut: {len(existing)} satir\n")

    new_rows = []

    # 1. Uniswap V2 factory'den otomatik pair adresleri
    uni_pairs = get_uniswap_v2_pairs(api_key, count=20)
    print()
    process_addresses(uni_pairs, "FACTORY_ATTACK", "UniV2Pair", api_key, seen, new_rows)

    # 2. DeFi Llama protokol adresleri -> REENTRANCY (CALL+SSTORE yogun)
    llama_addrs = get_defillama_contracts()
    print()
    process_addresses(llama_addrs, "REENTRANCY", "DeFiLlama", api_key, seen, new_rows)

        # 3. CoinGecko ERC20 tokenlar → STORAGE_MANIP (mapping+SSTORE yogun)
    cg_addrs = get_coingecko_tokens(limit=120)
    print()
    process_addresses(cg_addrs, "STORAGE_MANIP", "CoinGecko_ERC20", api_key, seen, new_rows)

    # 3. Sabit adresler
    print("[*] Sabit adresler isleniyor...\n")
    process_addresses(REENTRANCY_CONTRACTS,  "REENTRANCY",         "DeFi",    api_key, seen, new_rows)
    process_addresses(DELEGATECALL_CONTRACTS,"DELEGATECALL_ABUSE", "Proxy",   api_key, seen, new_rows)
    process_addresses(STORAGE_CONTRACTS,     "STORAGE_MANIP",      "SSTORE",  api_key, seen, new_rows)
    process_addresses(FACTORY_CONTRACTS,     "FACTORY_ATTACK",     "Factory", api_key, seen, new_rows)

    if not new_rows:
        print("Eklenecek yeni satir yok."); return

    all_rows = existing + new_rows
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bytecode", "label", "attack_type", "description"])
        w.writeheader()
        w.writerows(all_rows)

    counts = Counter(r["attack_type"] for r in all_rows)
    print(f"\n[+] +{len(new_rows)} yeni, toplam {len(all_rows)}")
    for k in ["BENIGN", "REENTRANCY", "SELFDESTRUCT", "DELEGATECALL_ABUSE",
              "FACTORY_ATTACK", "STORAGE_MANIP", "OBFUSCATED"]:
        print(f"    {k:<20}: {counts.get(k, 0)}")
    print("\nSonraki adim: docker compose exec ai-agent python ml/train.py")


if __name__ == "__main__":
    main()