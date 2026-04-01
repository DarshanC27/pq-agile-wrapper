#!/usr/bin/env python3
"""
"Harvest and Hack" Simulation
==============================

THE PITCH CENTREPIECE — Run this to demonstrate the entire value proposition.

This script simulates a complete "Harvest Now, Decrypt Later" attack:

  1. A sensitive data packet (Surrey satellite key) is created
  2. SCENARIO A: Protected ONLY by RSA-2048 (classical)
     → Attacker "breaks" RSA with a simulated quantum computer
     → Data is fully exposed
  3. SCENARIO B: Protected by RSA-2048 + ML-KEM Shadow Wrap (hybrid)
     → Attacker "breaks" RSA with a simulated quantum computer
     → But the data remains scrambled by the lattice-based layer
     → Attack FAILS

This proves the core thesis: even if classical encryption falls,
the Shadow Wrap keeps data safe.

Usage:
    python demo/harvest_and_hack.py
"""

import os
import sys
import time
import hashlib
import base64

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.crypto_engine import CryptoEngine
from src.config import load_config


# ANSI colours for dramatic terminal output
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   "HARVEST AND HACK" SIMULATION                             ║
║   PQ Agile Wrapper — Team UoSurrey                          ║
║                                                              ║
║   Demonstrating protection against HNDL attacks              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")


def simulate_rsa_encryption(plaintext: bytes) -> tuple:
    """
    Simulate RSA-2048 encryption (using AES as a stand-in).
    Returns (ciphertext, rsa_key) — in reality this would be RSA.
    """
    # Simulate an RSA session key
    rsa_key = os.urandom(32)
    # "Encrypt" with the RSA session key (simplified)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(rsa_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, rsa_key, nonce


def simulate_quantum_attack(rsa_key: bytes) -> bytes:
    """
    Simulate a quantum computer breaking RSA-2048.
    In reality, Shor's algorithm would factor the RSA modulus.
    Here we just "recover" the key to show the concept.
    """
    time.sleep(0.5)  # Dramatic pause
    return rsa_key  # Quantum computer recovers the key


def main():
    banner()
    setup_logger(level="WARNING", fmt="plain")

    # ================================================================
    # THE SENSITIVE DATA
    # ================================================================
    secret_data = (
        b"SURREY SATELLITE KEY: SSTL-07-UPLINK\n"
        b"Algorithm: AES-256-GCM\n"
        b"Key: 4a8f2c1b9e7d3a6f0c5b8e2d1a4f7c9e3b6d0a8f5c2e1b4d7a0f3c6e9b2d5a\n"
        b"Valid: 2026-01-01 to 2055-12-31\n"
        b"Classification: UK OFFICIAL-SENSITIVE\n"
        b"Owner: Surrey Satellite Technology Ltd\n"
    )

    print(f"{C.BOLD}[TARGET DATA]{C.RESET}")
    print(f"{C.DIM}{'─' * 60}{C.RESET}")
    print(f"{C.YELLOW}{secret_data.decode()}{C.RESET}")
    print(f"{C.DIM}{'─' * 60}{C.RESET}")
    print(f"  Size: {len(secret_data)} bytes")
    print(f"  Shelf life: 30 years (expires 2055)")
    print(f"  NCSC status: {C.RED}REQUIRES PQ PROTECTION{C.RESET}")
    print()

    input(f"{C.DIM}Press Enter to begin the simulation...{C.RESET}")
    print()

    # ================================================================
    # SCENARIO A: Classical RSA-2048 Only
    # ================================================================
    print(f"{C.RED}{C.BOLD}{'═' * 60}")
    print(f"  SCENARIO A: RSA-2048 Only (No Shadow Wrap)")
    print(f"{'═' * 60}{C.RESET}")
    print()

    # Step 1: Encrypt with RSA
    print(f"  {C.BLUE}[1] Encrypting with RSA-2048...{C.RESET}")
    rsa_ct, rsa_key, rsa_nonce = simulate_rsa_encryption(secret_data)
    print(f"      Ciphertext: {rsa_ct[:32].hex()}...")
    print(f"      Size: {len(rsa_ct)} bytes")
    print()

    # Step 2: Attacker harvests the ciphertext
    print(f"  {C.YELLOW}[2] Attacker harvests encrypted packet...{C.RESET}")
    harvested_a = rsa_ct
    print(f"      Stored: {len(harvested_a)} bytes captured and archived")
    print(f"      Attacker waits for quantum computer...")
    time.sleep(1)
    print()

    # Step 3: Years later — quantum attack
    print(f"  {C.RED}[3] YEAR 2035: Quantum computer available!{C.RESET}")
    print(f"      Running Shor's algorithm against RSA-2048...")
    recovered_key = simulate_quantum_attack(rsa_key)
    print(f"      {C.RED}{C.BOLD}RSA KEY RECOVERED!{C.RESET}")
    print()

    # Step 4: Decrypt with recovered key
    print(f"  {C.RED}[4] Decrypting harvested data...{C.RESET}")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(recovered_key)
    decrypted_a = aesgcm.decrypt(rsa_nonce, harvested_a, None)
    print()
    print(f"  {C.RED}{C.BOLD}╔══ DATA FULLY EXPOSED ══╗{C.RESET}")
    print(f"  {C.RED}{decrypted_a.decode()}{C.RESET}")
    print(f"  {C.RED}{C.BOLD}╚════════════════════════╝{C.RESET}")
    print()
    print(f"  {C.RED}RESULT: TOTAL COMPROMISE. Satellite key is in attacker's hands.{C.RESET}")
    print()

    input(f"{C.DIM}Press Enter for Scenario B (with Shadow Wrap)...{C.RESET}")
    print()

    # ================================================================
    # SCENARIO B: RSA-2048 + ML-KEM Shadow Wrap
    # ================================================================
    print(f"{C.GREEN}{C.BOLD}{'═' * 60}")
    print(f"  SCENARIO B: RSA-2048 + ML-KEM Shadow Wrap (Hybrid)")
    print(f"{'═' * 60}{C.RESET}")
    print()

    # Step 1: Encrypt with RSA (same as before)
    print(f"  {C.BLUE}[1] Encrypting with RSA-2048 (legacy layer)...{C.RESET}")
    rsa_ct_b, rsa_key_b, rsa_nonce_b = simulate_rsa_encryption(secret_data)
    print(f"      RSA ciphertext: {rsa_ct_b[:32].hex()}...")
    print()

    # Step 2: Apply Shadow Wrap (ML-KEM layer)
    print(f"  {C.CYAN}[2] Applying ML-KEM Shadow Wrap...{C.RESET}")
    engine = CryptoEngine(algorithm="Kyber768")
    wrapped, _ = engine.wrap_and_unwrap_demo(rsa_ct_b)
    wrapped_bytes = wrapped.to_bytes()
    print(f"      ML-KEM algorithm: Kyber768 (NIST FIPS 203)")
    print(f"      KEM ciphertext: {len(wrapped.kem_ciphertext)} bytes")
    print(f"      Encrypted payload: {len(wrapped.encrypted_payload)} bytes")
    print(f"      Total packet: {len(wrapped_bytes)} bytes")
    overhead = len(wrapped_bytes) - len(rsa_ct_b)
    print(f"      Overhead: +{overhead} bytes ({overhead/len(rsa_ct_b)*100:.1f}%)")
    print()

    # Step 3: Attacker harvests
    print(f"  {C.YELLOW}[3] Attacker harvests encrypted packet...{C.RESET}")
    harvested_b = wrapped_bytes
    print(f"      Stored: {len(harvested_b)} bytes captured and archived")
    print(f"      Attacker waits for quantum computer...")
    time.sleep(1)
    print()

    # Step 4: Quantum attack on RSA layer
    print(f"  {C.YELLOW}[4] YEAR 2035: Quantum computer available!{C.RESET}")
    print(f"      Running Shor's algorithm against RSA-2048...")
    recovered_key_b = simulate_quantum_attack(rsa_key_b)
    print(f"      {C.YELLOW}RSA key recovered... but the data is still wrapped!{C.RESET}")
    print()

    # Step 5: Attacker tries to read the data
    print(f"  {C.GREEN}[5] Attacker attempts to decrypt...{C.RESET}")
    print(f"      Even with the RSA key, the attacker sees:")
    print()

    # Show what the attacker actually gets — lattice noise
    lattice_noise = wrapped.encrypted_payload
    noise_preview = lattice_noise[:64].hex()
    print(f"  {C.MAGENTA}{C.BOLD}╔══ ATTACKER SEES ══╗{C.RESET}")
    print(f"  {C.MAGENTA}  {noise_preview[:32]}{C.RESET}")
    print(f"  {C.MAGENTA}  {noise_preview[32:]}{C.RESET}")
    print(f"  {C.MAGENTA}  ... ({len(lattice_noise)} bytes of lattice noise){C.RESET}")
    print(f"  {C.MAGENTA}{C.BOLD}╚═══════════════════╝{C.RESET}")
    print()
    print(f"  {C.GREEN}The data is encrypted under ML-KEM (Kyber768).{C.RESET}")
    print(f"  {C.GREEN}No known quantum algorithm can solve the lattice problem.{C.RESET}")
    print(f"  {C.GREEN}The satellite key remains SAFE.{C.RESET}")
    print()

    # ================================================================
    # SUMMARY
    # ================================================================
    print(f"{C.BOLD}{'═' * 60}")
    print(f"  SIMULATION SUMMARY")
    print(f"{'═' * 60}{C.RESET}")
    print()
    print(f"  {C.RED}Scenario A (RSA only):     DATA COMPROMISED{C.RESET}")
    print(f"  {C.GREEN}Scenario B (RSA + ML-KEM): DATA PROTECTED {C.RESET}")
    print()
    print(f"  The Shadow Wrap added only {C.CYAN}{overhead} bytes{C.RESET} of overhead")
    print(f"  and required {C.CYAN}zero changes{C.RESET} to the legacy application.")
    print()
    print(f"  {C.BOLD}This is why we need PQ protection NOW — not in 2035.{C.RESET}")
    print()
    print(f"{C.DIM}  Crypto engine stats: {engine.stats}{C.RESET}")
    print()


if __name__ == "__main__":
    main()
