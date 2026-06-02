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
    "DIRECT_ETH_TRANSFER":      "FACTORY_ATTACK",
    "UNKNOWN_SELECTOR":         "OBFUSCATED",
    "TX_ORIGIN_EXPLOIT":        "DELEGATECALL_ABUSE",
    "OVERFLOW_ATTEMPT":         "STORAGE_MANIP",
    "FRONTRUN_TIMESTAMP_MANIP": "STORAGE_MANIP",
}