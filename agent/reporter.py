import json
from datetime import datetime, timezone
from web3 import Web3
from agent.config import THREAT_RULES

SEVERITY_COLOR = {"LOW": "\033[32m", "MEDIUM": "\033[33m",
                  "HIGH": "\033[91m", "CRITICAL": "\033[1;91m"}
RESET = "\033[0m"


def build_report(event, attack_class, confidence, is_contract, features) -> dict:
    rules      = THREAT_RULES.get(attack_class, THREAT_RULES["BENIGN"])
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