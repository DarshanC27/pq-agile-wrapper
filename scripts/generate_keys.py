#!/usr/bin/env python3
"""
Standalone Key Generation Script
=================================

Generate ML-KEM keypairs for the Shadow Proxy.
Useful for pre-provisioning keys or testing.

Usage:
    python scripts/generate_keys.py --algorithm Kyber768 --count 5
    python scripts/generate_keys.py --algorithm Kyber1024 --output ./my_keys
"""

import os
import sys
import json
import argparse
import hashlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.crypto_engine import CryptoEngine


def main():
    parser = argparse.ArgumentParser(
        description="Generate ML-KEM keypairs for the Shadow Proxy"
    )
    parser.add_argument(
        "--algorithm", "-a",
        choices=["Kyber512", "Kyber768", "Kyber1024"],
        default="Kyber768",
        help="ML-KEM algorithm variant (default: Kyber768)",
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=1,
        help="Number of keypairs to generate (default: 1)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./data/keys",
        help="Output directory for key files (default: ./data/keys)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["hex", "json"],
        default="json",
        help="Output format (default: json)",
    )
    args = parser.parse_args()

    setup_logger(level="INFO", fmt="plain")
    engine = CryptoEngine(algorithm=args.algorithm)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nGenerating {args.count} {args.algorithm} keypair(s)...")
    print(f"Backend: {engine.backend}")
    print(f"Output: {output_dir}\n")

    for i in range(args.count):
        keypair = engine.generate_keypair()
        key_id = hashlib.sha256(keypair.public_key).hexdigest()[:16]

        if args.format == "json":
            key_data = {
                "key_id": key_id,
                "algorithm": keypair.algorithm,
                "public_key": keypair.public_key.hex(),
                "secret_key": keypair.secret_key.hex(),
                "public_key_size": len(keypair.public_key),
                "secret_key_size": len(keypair.secret_key),
                "generated_at": keypair.generated_at,
            }
            filepath = output_dir / f"keypair_{key_id}.json"
            with open(filepath, "w") as f:
                json.dump(key_data, f, indent=2)
        else:
            filepath = output_dir / f"keypair_{key_id}.hex"
            with open(filepath, "w") as f:
                f.write(f"# ML-KEM Keypair: {key_id}\n")
                f.write(f"# Algorithm: {keypair.algorithm}\n")
                f.write(f"PUBLIC_KEY={keypair.public_key.hex()}\n")
                f.write(f"SECRET_KEY={keypair.secret_key.hex()}\n")

        print(f"  [{i+1}/{args.count}] Key {key_id} → {filepath}")

    print(f"\nDone. Generated {args.count} keypair(s) in {output_dir}")
    print(f"Crypto stats: {engine.stats}")


if __name__ == "__main__":
    main()
