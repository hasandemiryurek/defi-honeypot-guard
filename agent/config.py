import os, logging

GUARDIAN_KEY  = os.getenv("GUARDIAN_KEY", "")
RPC_URL       = os.getenv("RPC_URL", "http://127.0.0.1:8545")
SHARED_DIR    = os.getenv("SHARED_DIR", ".")
MODEL_PATH    = os.getenv("MODEL_PATH", "honeypot_ai_model.pkl")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("honeypot-agent")

THREAT_RULES = {
    "REENTRANCY": {
        "severity": "CRITICAL",
        "mitre": "CAPEC-17: Smart Contract Reentrancy",
        "iocs": [
            "SSTORE (0x55) not cleared before CALL (0xf1) opcode",
            "Same function re-entered within a single transaction",
            "withdraw() call present inside receive() / fallback()",
        ],
        "defenses": [
            "Apply Checks-Effects-Interactions (CEI) pattern",
            "Use OpenZeppelin ReentrancyGuard modifier",
            "Prefer pull-payment pattern over push",
        ],
        "summary": (
            "Reentrancy attack: contract does not zero the balance before sending ETH. "
            "Attacker re-invokes withdraw() from their own receive() function, "
            "draining funds repeatedly. The DAO hack exploited this flaw for ~$60M."
        ),
    },
    "SELFDESTRUCT": {
        "severity": "HIGH",
        "mitre": "CAPEC-175: SELFDESTRUCT Griefing",
        "iocs": [
            "0xff (SELFDESTRUCT) opcode present in bytecode",
            "Contract can self-destruct and forward entire balance to target address",
        ],
        "defenses": [
            "Audit all SELFDESTRUCT usage in contracts",
            "Restrict selfdestruct() calls with onlyOwner modifier",
            "Protect upgradeable proxy implementation contracts",
        ],
        "summary": (
            "SELFDESTRUCT attack: destruction opcode detected in bytecode. "
            "Contract can transfer its entire balance to a specified address and be removed from chain."
        ),
    },
    "DELEGATECALL_ABUSE": {
        "severity": "CRITICAL",
        "mitre": "CAPEC-22: DELEGATECALL Proxy Hijack",
        "iocs": [
            "High density of 0xf4 (DELEGATECALL) opcode",
            "External contract code executing in caller's storage context",
            "Owner variable overwritable via storage slot collision",
        ],
        "defenses": [
            "Only DELEGATECALL to trusted implementation addresses",
            "Use OpenZeppelin TransparentUpgradeableProxy",
            "Make implementation address immutable or add a timelock",
        ],
        "summary": (
            "DELEGATECALL abuse: external code runs inside the caller contract's storage. "
            "Attacker can overwrite the owner address and take full control."
        ),
    },
    "FACTORY_ATTACK": {
        "severity": "HIGH",
        "mitre": "CAPEC-13: Malicious Contract Factory",
        "iocs": [
            "Heavy use of 0xf0 (CREATE) or 0xf5 (CREATE2) opcodes",
            "Deploying malicious code to pre-computed addresses via CREATE2",
        ],
        "defenses": [
            "Validate addresses received from external factory contracts",
            "Verify bytecode hash of CREATE2-deployed contracts",
        ],
        "summary": (
            "Factory attack: many contracts deployed via CREATE/CREATE2. "
            "Attacker plants malicious contracts at known addresses."
        ),
    },
    "STORAGE_MANIP": {
        "severity": "MEDIUM",
        "mitre": "CAPEC-165: Storage Slot Collision",
        "iocs": [
            "High SSTORE (0x55) opcode density without external calls",
            "Attempt to write directly to critical storage slots",
        ],
        "defenses": [
            "Protect storage access with access control modifiers",
            "Declare critical variables private and add setter guards",
        ],
        "summary": (
            "Storage manipulation: high SSTORE density detected. "
            "Attacker attempts to overwrite critical state variables "
            "to seize control of the contract."
        ),
    },
    "OBFUSCATED": {
        "severity": "MEDIUM",
        "mitre": "CAPEC-267: Bytecode Obfuscation",
        "iocs": [
            "Abnormally high JUMP/JUMPI (0x56/0x57) density",
            "Real attack vector may be hidden",
        ],
        "defenses": [
            "Run deep analysis with symbolic execution (Mythril, Manticore)",
            "Inspect bytecode with a decompiler (Dedaub, Heimdall)",
        ],
        "summary": (
            "Obfuscated bytecode: control flow contains far more conditional branches "
            "than normal. The actual attack logic may be concealed."
        ),
    },
    "BENIGN": {
        "severity": "LOW",
        "mitre": "N/A",
        "iocs": ["No known malicious opcode pattern detected"],
        "defenses": ["Standard security audit is sufficient"],
        "summary": "Normal contract behaviour. No known attack pattern detected.",
    },
}

SIGNAL_TO_CLASS = {
    "REENTRANCY_WITHDRAW":      "REENTRANCY",
    "DIRECT_ETH_TRANSFER":      "FACTORY_ATTACK",
    "UNKNOWN_SELECTOR":         "OBFUSCATED",
    "TX_ORIGIN_EXPLOIT":        "DELEGATECALL_ABUSE",
    "DELEGATECALL_ABUSE":       "DELEGATECALL_ABUSE",
    "DELEGATECALL_ATTEMPT":     "DELEGATECALL_ABUSE",
    "OVERFLOW_ATTEMPT":         "STORAGE_MANIP",
    "FRONTRUN_TIMESTAMP_MANIP": "STORAGE_MANIP",
}