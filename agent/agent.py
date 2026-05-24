#!/usr/bin/env python3
import time
import joblib
from pathlib import Path
from web3 import Web3

from agent.config import log, RPC_URL, SHARED_DIR, MODEL_PATH, POLL_INTERVAL, SIGNAL_TO_CLASS
from agent.features import extract_features
from agent.blockchain import connect_web3, load_contract, pause_contract, parse_sus, parse_withdraw
from agent.reporter import build_report, print_report, save_report


def load_model(model_path: str):
    if not Path(model_path).exists():
        log.warning("Model bulunamadi, train.py calistiriliyor...")
        import subprocess
        subprocess.run(["python", "train.py"], check=True)
    data  = joblib.load(model_path)
    log.info("Model yuklendi | Siniflar: %s", list(data["label_encoder"].classes_))
    return data["model"], data["label_encoder"]


def classify(model, le, w3: Web3, address: str, event_signal: str) -> tuple:
    bytecode    = w3.eth.get_code(address).hex()
    is_contract = len(bytecode) > 2
    if not is_contract:
        return SIGNAL_TO_CLASS.get(event_signal, "BENIGN"), 0.55, False, [0.0] * 20
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


def main():
    log.info("Honeypot AI Monitor baslatiliyor...")
    w3       = connect_web3(RPC_URL)
    model, le = load_model(MODEL_PATH)
    contract  = load_contract(w3, SHARED_DIR)
    sus_f     = contract.events.SuspiciousActivity.create_filter(from_block="latest")
    wd_f      = contract.events.WithdrawAttempt.create_filter(from_block="latest")
    log.info("Monitor aktif — saldiri bekleniyor...")

    while True:
        try:
            events  = [parse_sus(e) for e in sus_f.get_new_entries()]
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