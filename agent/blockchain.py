import json, time
from pathlib import Path
from web3 import Web3
from agent.config import log, GUARDIAN_KEY

def connect_web3(rpc_url: str) -> Web3:
    for i in range(10):
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if w3.is_connected():
            log.info("Blockchain: %s (chain %s)", rpc_url, w3.eth.chain_id)
            return w3
        log.warning("Connection waiting %d/10", i + 1)
        time.sleep(3)
    raise RuntimeError(f"RPC connection failed: {rpc_url}")


def load_contract(w3, shared_dir):
    addr_file = Path(shared_dir) / "contract_address.txt"
    abi_file  = Path("artifacts/contracts/HoneypotAdvanced.sol/HoneypotAdvanced.json")
    for _ in range(60):
        if addr_file.exists(): break
        log.info("Deploy waiting..."); time.sleep(3)
    else:
        raise RuntimeError("contract_address.txt could not be created")
    address = addr_file.read_text().strip()
    log.info("Honeypot: %s", address)
    with abi_file.open() as f:
        abi = json.load(f)["abi"]
    return w3.eth.contract(address=address, abi=abi)


def pause_contract(w3: Web3, contract, reason: str):
    if not GUARDIAN_KEY:
        log.warning("GUARDIAN_KEY not defined, skipping pause")
        return
    try:
        account = w3.eth.account.from_key(GUARDIAN_KEY)
        tx = contract.functions.pause(reason).build_transaction({
            "from":     account.address,
            "nonce":    w3.eth.get_transaction_count(account.address),
            "gas":      100000,
            "gasPrice": w3.eth.gas_price,
        })
        signed  = w3.eth.account.sign_transaction(tx, GUARDIAN_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        log.warning("CONTRACT PAUSED — reason: %s | tx: %s", reason, tx_hash.hex())
    except Exception as exc:
        log.error("Pause error: %s", exc)


def parse_sus(evt) -> dict:
    a = evt["args"]
    return {"attackType": a["attackType"], "actor": a["actor"],
            "value": a["value"], "data": a["data"].hex() if a["data"] else "",
            "txHash": evt["transactionHash"].hex()}


def parse_withdraw(evt) -> dict:
    a = evt["args"]
    return {"attackType": "REENTRANCY_WITHDRAW", "actor": a["user"],
            "value": a["amount"], "data": "", "txHash": evt["transactionHash"].hex()}