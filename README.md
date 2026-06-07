# DeFi Honeypot Guard 

Ethereum akıllı kontrat saldırılarını tespit eden, makine öğrenmesi destekli honeypot sistemi. Saldırı kontratlarını EVM bytecode analizi ile sınıflandırır ve gerçek zamanlı dashboard üzerinden raporlar.

---

## Kullanılan Teknolojiler

### Blockchain
| Teknoloji | Versiyon | Kullanım |
| :--- | :--- | :--- |
| **Hardhat** | `^2.22.2` | Yerel Ethereum geliştirme ortamı |
| **Solidity** | `^0.8.24` | Akıllı kontrat dili |
| **ethers.js** | `^6.16.0` | Blockchain etkileşimi (JavaScript) |
| **web3.py** | `>=6.15.0` | Blockchain etkileşimi (Python/Agent) |

### Makine Öğrenmesi
| Teknoloji | Kullanım |
| :--- | :--- |
| **scikit-learn** | RandomForest + GradientBoosting modeli |
| **imbalanced-learn** | SMOTE ile veri dengeleme |
| **joblib** | Model kaydetme/yükleme (`.pkl`) |
| **pandas / numpy** | Veri işleme |

### Backend / Agent
| Teknoloji | Kullanım |
| :--- | :--- |
| **Python 3** | Agent ve ML pipeline |
| **FastAPI** | Dashboard API sunucusu |
| **uvicorn** | ASGI web sunucusu |

### Frontend
| Teknoloji | Kullanım |
| :--- | :--- |
| **HTML + JavaScript** | Dashboard arayüzü (framework yok) |
| **Fetch API** | Agent raporlarını polling ile çeker |

### Altyapı
| Teknoloji | Kullanım |
| :--- | :--- |
| **Docker** | Her servis izole konteyner |
| **Docker Compose** | Çok servisli orkestrasyon |
| **Docker Named Volume** | Kontrat adresi paylaşımı (`shared-data`) |
| **Node.js 20 Alpine** | Hardhat ve deployer imajı |

---

##  Proje Yapısı

```text
defi-honeypot-guard/
├── contracts/
│   ├── HoneypotAdvanced.sol        # Tuzak kontrat — saldırıları tespit eder
│   ├── AttackerContract.sol        # Reentrancy saldırısı
│   ├── AttackerDelegatecall.sol    # DELEGATECALL / owner ele geçirme
│   ├── AttackerFactory.sol         # CREATE2 factory saldırısı
│   ├── AttackerStorageManip.sol    # Storage manipülasyon / overflow
│   └── AttackerObfuscated.sol      # Obfuscated bytecode simülasyonu
├── agent/
│   ├── agent.py                    # Ana döngü — event dinle, sınıflandır, raporla
│   ├── blockchain.py               # Web3 bağlantı, kontrat yükleme, pause
│   ├── config.py                   # Ayarlar, THREAT_RULES, SIGNAL_TO_CLASS
│   ├── features.py                 # Bytecode → 26 ML özelliği
│   └── reporter.py                 # Rapor üretimi ve JSON kaydetme
├── ml/
│   ├── train.py                    # Model eğitimi (VotingClassifier + kalibrasyon)
│   ├── mini_dataset.csv            # Eğitim verisi
│   └── extract_artifacts.py        # Hardhat artifact'larından bytecode çıkarma
├── dashboard/
│   ├── dashboard.py                # FastAPI sunucusu
│   └── dashboard.html              # Web arayüzü
├── scripts/
│   ├── deploy.js                   # HoneypotAdvanced deploy
│   ├── attack_ml_demo.js           # Tüm saldırıları çalıştıran demo
│   ├── attack_reentrancy.js        # Sadece reentrancy testi
│   └── unpause.js                  # Honeypot'u manuel açma
├── Dockerfile                      # Agent imajı
├── Dockerfile.dashboard            # Dashboard imajı
├── docker-compose.yml              # Tüm servislerin konfigürasyonu
├── hardhat.config.js               # Hardhat ağ ayarları
└── requirements.txt                # Python bağımlılıkları
