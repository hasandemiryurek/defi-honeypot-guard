#!/usr/bin/env python3
"""
Honeypot AI Monitör — Tamamen yerel, dış API yok.
Pipeline: Web3 event → RandomForest (çok sınıflı) → kural tabanlı tehdit raporu
"""

import os, json, time, logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
from web3 import Web3

GUARDIAN_KEY = os.getenv("GUARDIAN_KEY", "")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("honeypot-agent")

RPC_URL       = os.getenv("RPC_URL", "http://127.0.0.1:8545")
SHARED_DIR    = os.getenv("SHARED_DIR", ".")
MODEL_PATH    = os.getenv("MODEL_PATH", "honeypot_ai_model.pkl")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))

# Her saldırı sınıfı için tehdit istihbaratı kuralları
THREAT_RULES = {
    "REENTRANCY": {
        "severity": "CRITICAL",
        "mitre": "CAPEC-17: Smart Contract Reentrancy",
        "iocs": [
            "CALL (0xf1) opcode oncesinde SSTORE (0x55) sifirlanmiyor",
            "Tek transaction icinde ayni fonksiyon tekrar cagriliyor",
            "receive() / fallback() icinde withdraw() cagrisi mevcut",
        ],
        "defenses": [
            "Checks-Effects-Interactions (CEI) pattern uygula",
            "OpenZeppelin ReentrancyGuard modifier kullan",
            "Pull-payment pattern tercih et",
        ],
        "summary": (
            "Reentrancy saldirisi: sozlesme ETH gondermeden once bakiyeyi sifirlamiyor. "
            "Saldirgan kendi receive() fonksiyonunda tekrar withdraw() cagirarak "
            "fonlari defalarca cekebilir. The DAO hack bu aciкla ~$60M calmistir."
        ),
    },
    "SELFDESTRUCT": {
        "severity": "HIGH",
        "mitre": "CAPEC-175: SELFDESTRUCT Griefing",
        "iocs": [
            "Bytecode icinde 0xff (SELFDESTRUCT) opcode mevcut",
            "Sozlesme kendini yok edip tum bakiyeyi hedef adrese gonderebilir",
        ],
        "defenses": [
            "Sozlesmelerde SELFDESTRUCT kullanimini denetle",
            "selfdestruct() cagrisini onlyOwner ile sinirla",
            "Upgradeable proxy implementation sozlesmelerini koru",
        ],
        "summary": (
            "SELFDESTRUCT saldirisi: bytecode'da yikim opcode'u tespit edildi. "
            "Sozlesme tum bakiyesini belirtilen adrese transfer edip zincirden silinebilir."
        ),
    },
    "DELEGATECALL_ABUSE": {
        "severity": "CRITICAL",
        "mitre": "CAPEC-22: DELEGATECALL Proxy Hijack",
        "iocs": [
            "0xf4 (DELEGATECALL) opcode yuksek yogunlukta",
            "Harici sozlesmenin kodu caller'in storage'inda calisiyor",
            "Storage slot cakismasi ile owner degiskeni uzerine yazilabilir",
        ],
        "defenses": [
            "DELEGATECALL yalnizca guvenilir implementation adreslerine yap",
            "OpenZeppelin TransparentUpgradeableProxy kullan",
            "Implementation adresini immutable yap veya timelock koy",
        ],
        "summary": (
            "DELEGATECALL kotüye kullanimi: harici kod caller sozlesmesinin "
            "storage'inda calisiyor. Saldirgan owner adresini degistirebilir."
        ),
    },
    "FACTORY_ATTACK": {
        "severity": "HIGH",
        "mitre": "CAPEC-13: Malicious Contract Factory",
        "iocs": [
            "0xf0 (CREATE) veya 0xf5 (CREATE2) opcode yogun kullanimi",
            "CREATE2 ile onceden hesaplanan adrese kotü amacli kod yerlestirme",
        ],
        "defenses": [
            "Dis factory sozlesmelerinden gelen adresleri dogrula",
            "CREATE2 ile deploy edilen sozlesmelerin bytecode hash'ini kontrol et",
        ],
        "summary": (
            "Factory saldirisi: CREATE/CREATE2 ile cok sayida sozlesme deploy ediliyor. "
            "Saldirgan bilinen adreslere zarali sozlesmeler yerlestiriyor."
        ),
    },
    "STORAGE_MANIP": {
        "severity": "MEDIUM",
        "mitre": "CAPEC-165: Storage Slot Collision",
        "iocs": [
            "0x55 (SSTORE) opcode yogun kullanimi, external call olmaksizin",
            "Kritik storage slot'larina dogrudan yazma girisimi",
        ],
        "defenses": [
            "Storage erisimini access control modifier ile koru",
            "Kritik degiskenleri private yap, setter kontrolu ekle",
        ],
        "summary": (
            "Storage manipülasyonu: yoğun SSTORE kullanimi tespit edildi. "
            "Saldirgan kritik durum degiskenlerine dogrudan yazarak "
            "sozlesme kontrolunu ele gecirmeye calisiyor."
        ),
    },
    "OBFUSCATED": {
        "severity": "MEDIUM",
        "mitre": "CAPEC-267: Bytecode Obfuscation",
        "iocs": [
            "Anormal yuksek JUMP/JUMPI (0x56/0x57) yogunlugu",
            "Gercek saldiri vektoru gizlenmis olabilir",
        ],
        "defenses": [
            "Symbolic execution ile (Mythril, Manticore) derin analiz yap",
            "Bytecode'u decompiler ile (Dedaub, Heimdall) incele",
        ],
        "summary": (
            "Gizlenmis bytecode: kontrolun akisi normalden cok daha fazla "
            "kosullu dal iceriyor. Gercek saldiri mantigi gizlenmis olabilir."
        ),
    },
    "BENIGN": {
        "severity": "LOW",
        "mitre": "N/A",
        "iocs": ["Bilinen zararli opcode pattern'i tespit edilmedi"],
        "defenses": ["Standart guvenlik denetimi yeterli"],
        "summary": "Normal sozlesme davranisi. Bilinen saldiri pattern'i tespit edilmedi.",
    },
}

SIGNAL_TO_CLASS = {
    "REENTRANCY_WITHDRAW":      "REENTRANCY",
    "DIRECT_ETH_TRANSFER":      "BENIGN",
    "UNKNOWN_SELECTOR":         "OBFUSCATED",
    "TX_ORIGIN_EXPLOIT":        "DELEGATECALL_ABUSE",
    "OVERFLOW_ATTEMPT":         "STORAGE_MANIP",
    "FRONTRUN_TIMESTAMP_MANIP": "STORAGE_MANIP",
}


def extract_features(bytecode: str) -> list:
    code = bytecode.replace("0x", "").lower()
    if len(code) < 4:
        return [0.0] * 12
    bytes_list   = [code[i:i+2] for i in range(0, len(code), 2)]
    total        = len(bytes_list) or 1
    call_f1      = sum(1 for b in bytes_list if b == "f1")
    call_f2      = sum(1 for b in bytes_list if b == "f2")
    call_f4      = sum(1 for b in bytes_list if b == "f4")
    call_fa      = sum(1 for b in bytes_list if b == "fa")
    call_ops     = call_f1 + call_f2 + call_f4 + call_fa
    selfdestruct = sum(1 for b in bytes_list if b == "ff")
    create_ops   = sum(1 for b in bytes_list if b in ("f0", "f5"))
    sstore       = sum(1 for b in bytes_list if b == "55")
    sload        = sum(1 for b in bytes_list if b == "54")
    jumpi_count  = sum(1 for b in bytes_list if b == "57")
    jump_count   = sum(1 for b in bytes_list if b == "56")
    jump_density = (jump_count + jumpi_count) / total
    f_density    = code.count("f") / len(code)
    ff_density   = selfdestruct / total
    return [
        len(code), f_density, call_ops, selfdestruct, create_ops,
        sstore, sload, jump_density,
        1.0 if call_ops > 0 and sstore > 0 else 0.0,
        call_f4 / call_ops if call_ops > 0 else 0.0,
        ff_density,
        1.0 if jumpi_count / total > 0.05 else 0.0,
    ]


def load_model(model_path: str):
    if not Path(model_path).exists():
        log.warning("Model bulunamadi, train.py calistiriliyor...")
        import subprocess
        subprocess.run(["python", "train.py"], check=True)
    data  = joblib.load(model_path)
    model = data["model"]
    le    = data["label_encoder"]
    log.info("Model yuklendi | Siniflar: %s", list(le.classes_))
    return model, le


def classify(model, le, w3: Web3, address: str, event_signal: str) -> tuple:
    bytecode    = w3.eth.get_code(address).hex()
    is_contract = len(bytecode) > 2

    if not is_contract:
        return SIGNAL_TO_CLASS.get(event_signal, "BENIGN"), 0.55, False, [0.0] * 12

    features     = extract_features(bytecode)
    label_id     = model.predict([features])[0]
    proba        = model.predict_proba([features])[0]
    attack_class = le.inverse_transform([label_id])[0]
    confidence   = float(proba[label_id])

    if confidence < 0.6:
        signal_class = SIGNAL_TO_CLASS.get(event_signal, attack_class)
        if signal_class != "BENIGN":
            attack_class = signal_class

    return attack_class, confidence, True, features


def build_report(event, attack_class, confidence, is_contract, features) -> dict:
    rules     = THREAT_RULES.get(attack_class, THREAT_RULES["BENIGN"])
    extra_iocs = []
    if features[2] > 5:  extra_iocs.append(f"Yuksek CALL opcode sayisi: {int(features[2])}")
    if features[3] > 0:  extra_iocs.append(f"SELFDESTRUCT sayisi: {int(features[3])}")
    if features[4] > 2:  extra_iocs.append(f"CREATE/CREATE2 sayisi: {int(features[4])}")
    if features[5] > 3:  extra_iocs.append(f"SSTORE sayisi: {int(features[5])}")
    return {
        "attack_class":             attack_class,
        "severity":                 rules["severity"],
        "confidence":               round(confidence * 100, 1),
        "is_contract":              is_contract,
        "mitre_technique":          rules["mitre"],
        "attacker_profile":         "MALICIOUS_CONTRACT" if is_contract else "EOA",
        "indicators_of_compromise": rules["iocs"] + extra_iocs,
        "recommended_defenses":     rules["defenses"],
        "summary":                  rules["summary"],
    }


SEVERITY_COLOR = {"LOW": "\033[32m", "MEDIUM": "\033[33m",
                  "HIGH": "\033[91m", "CRITICAL": "\033[1;91m"}
RESET = "\033[0m"


def print_report(event, report):
    sev   = report["severity"]
    color = SEVERITY_COLOR.get(sev, "")
    sep   = "=" * 70
    print(f"\n{color}{sep}")
    print(f"  [HONEYPOT] TEHDIT RAPORU — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep + RESET)
    print(f"  Adres    : {event.get('actor', '?')}")
    print(f"  Sinyal   : {event.get('attackType', '?')}")
    print(f"  Profil   : {report['attacker_profile']}")
    print(f"{color}  Siddet   : {sev}{RESET}")
    print(f"  Sinif    : {report['attack_class']}")
    print(f"  Guven    : %{report['confidence']}")
    print(f"  MITRE    : {report['mitre_technique']}")
    print(f"  ETH      : {Web3.from_wei(event.get('value', 0), 'ether')} ETH")
    print("\n  IOC:")
    for ioc in report["indicators_of_compromise"]:
        print(f"    • {ioc}")
    print("\n  Savunma:")
    for d in report["recommended_defenses"]:
        print(f"    • {d}")
    print(f"\n  Ozet: {report['summary']}")
    print(f"{color}{sep}{RESET}\n")


def save_report(event, report):
    record = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "event": event, "report": report}
    with open("threat_log.jsonl", "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def connect_web3(rpc_url: str) -> Web3:
    for i in range(10):
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if w3.is_connected():
            log.info("Blockchain: %s (chain %s)", rpc_url, w3.eth.chain_id)
            return w3
        log.warning("Baglanti bekleniyor %d/10...", i + 1)
        time.sleep(3)
    raise RuntimeError(f"RPC baglantilamadi: {rpc_url}")


def load_contract(w3, shared_dir):
    addr_file = Path(shared_dir) / "contract_address.txt"
    abi_file  = Path("artifacts/contracts/HoneypotAdvanced.sol/HoneypotAdvanced.json")
    for _ in range(60):
        if addr_file.exists(): break
        log.info("Deploy bekleniyor..."); time.sleep(3)
    else:
        raise RuntimeError("contract_address.txt olusмади")
    address = addr_file.read_text().strip()
    log.info("Honeypot: %s", address)
    with abi_file.open() as f:
        abi = json.load(f)["abi"]
    return w3.eth.contract(address=address, abi=abi)

def pause_contract(w3: Web3, contract, reason: str):
    if not GUARDIAN_KEY:
        log.warning("GUARDIAN_KEY tanimli degil, pause atlaниди")
        return
    try:
        account = w3.eth.account.from_key(GUARDIAN_KEY)
        tx = contract.functions.pause(reason).build_transaction({
            "from":     account.address,
            "nonce":    w3.eth.get_transaction_count(account.address),
            "gas":      100000,
            "gasPrice": w3.eth.gas_price,
        })
        signed = w3.eth.account.sign_transaction(tx, GUARDIAN_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        log.warning("KONTRAT DURDURULDU — sebep: %s | tx: %s", reason, tx_hash.hex())
    except Exception as exc:
        log.error("Pause hatasi: %s", exc)


def parse_sus(evt) -> dict:
    a = evt["args"]
    return {"attackType": a["attackType"], "actor": a["actor"],
            "value": a["value"], "data": a["data"].hex() if a["data"] else "",
            "txHash": evt["transactionHash"].hex()}


def parse_withdraw(evt) -> dict:
    a = evt["args"]
    return {"attackType": "REENTRANCY_WITHDRAW", "actor": a["user"],
            "value": a["amount"], "data": "", "txHash": evt["transactionHash"].hex()}


def main():
    log.info("Honeypot AI Monitor baslatiliyor (yerel model)...")
    w3            = connect_web3(RPC_URL)
    model, le     = load_model(MODEL_PATH)
    contract      = load_contract(w3, SHARED_DIR)
    sus_f         = contract.events.SuspiciousActivity.create_filter(from_block="latest")
    wd_f          = contract.events.WithdrawAttempt.create_filter(from_block="latest")
    log.info("Monitor aktif — saldiri bekleniyor...")

    while True:
        try:
            events = [parse_sus(e) for e in sus_f.get_new_entries()]
            events += [parse_withdraw(e) for e in wd_f.get_new_entries()]
            for event in events:
                attack_class, conf, is_contract, feats = \
                    classify(model, le, w3, event["actor"], event["attackType"])
                log.info("Olay: %s | Sinif: %s | Guven: %.1f%%",
                         event["attackType"], attack_class, conf * 100)
                report = build_report(event, attack_class, conf, is_contract, feats)
                print_report(event, report)
                save_report(event, report)
                if report["severity"] in ("HIGH", "CRITICAL"):
                    pause_contract(w3, contract, f"{report['attack_class']} tespit edildi")
             
        except Exception as exc:
            log.error("Hata: %s", exc, exc_info=True)
            time.sleep(5)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()