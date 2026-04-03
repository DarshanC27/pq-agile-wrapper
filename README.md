# PQ Agile Wrapper — "Shadow Proxy"

**Post-Quantum Crypto-Agile Security Sidecar for Legacy Systems**

> Protect your "eternal data" today — without touching a single line of application code.

---

## What Is This?

The PQ Agile Wrapper is a containerised edge proxy ("Security Sidecar") that wraps
existing network traffic in a **Post-Quantum (ML-KEM / Kyber)** encryption layer.
It uses the **Agile Mosca Protocol** to identify high-priority data streams and
apply hybrid classical + lattice-based encryption — defending against
"Harvest Now, Decrypt Later" (HNDL) attacks.

## Architecture

```
┌─────────────┐       ┌──────────────────────────┐       ┌──────────────┐
│  Client /    │──────▶│     Shadow Proxy          │──────▶│  Legacy      │
│  IoT Device  │       │  ┌────────────────────┐   │       │  Server /    │
│              │◀──────│  │ Metadata Evaluator │   │◀──────│  Database    │
└─────────────┘       │  │ Crypto Engine       │   │       └──────────────┘
                      │  │ Key Vault           │   │
                      │  │ Fail-Safe Monitor   │   │
                      │  └────────────────────┘   │
                      └──────────────────────────┘
```

## Quick Start

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd pq-agile-wrapper
pip install -r requirements.txt
```

### 2. Run with Docker (Recommended)

```bash
docker-compose up --build
```

### 3. Run Locally

```bash
python -m src.shadow_proxy --config config/default.yaml
```

### 4. Run the "Harvest and Hack" Demo

```bash
python demo/harvest_and_hack.py
```

## Project Structure

```
pq-agile-wrapper/
├── src/
│   ├── __init__.py
│   ├── config.py              # Configuration loader
│   ├── crypto_engine.py       # ML-KEM hybrid encryption core
│   ├── metadata_evaluator.py  # NCSC-aligned data classifier
│   ├── key_vault.py           # Lattice key generation & storage
│   ├── shadow_proxy.py        # Main TCP proxy server
│   ├── failsafe.py            # Fail-safe fallback logic
│   └── logger.py              # Structured logging
├── config/
│   └── default.yaml           # Default configuration
├── demo/
│   ├── legacy_server.py       # Mock legacy server for testing
│   ├── client.py              # Test client
│   └── harvest_and_hack.py    # Full HNDL attack simulation
├── tests/
│   ├── test_crypto_engine.py
│   ├── test_metadata_evaluator.py
│   └── test_key_vault.py
├── scripts/
│   └── generate_keys.py       # Standalone key generation
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Configuration

Edit `config/default.yaml` to set:
- Proxy listen/forward ports
- Data classification rules (shelf-life thresholds)
- ML-KEM security level (512 / 768 / 1024)
- Fail-safe behaviour
- Logging level

## NCSC 2035 Alignment

The metadata evaluator classifies data against the NCSC 2035 migration deadline:
- **Data expiry > 2035** → Apply ML-KEM Shadow Wrap (hybrid encryption)
- **Data expiry ≤ 2035** → Pass through with classical encryption only

## Key Technologies

- **ML-KEM (Kyber)** via `liboqs-python` — NIST FIPS 203 standard
- **Hybrid encryption** — AES-256-GCM + ML-KEM key encapsulation
- **Python asyncio** — high-performance async TCP proxy
- **Docker** — single-container deployment

