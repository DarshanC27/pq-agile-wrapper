"""
Tests for the Crypto Engine.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.crypto_engine import CryptoEngine, ShadowWrappedPacket


@pytest.fixture(autouse=True)
def init_logger():
    setup_logger(level="WARNING", fmt="plain")


class TestCryptoEngine:
    """Test the ML-KEM hybrid encryption engine."""

    def test_keypair_generation(self):
        engine = CryptoEngine(algorithm="Kyber768", backend="sim")
        keypair = engine.generate_keypair()

        assert keypair.algorithm == "Kyber768"
        assert len(keypair.public_key) == 1184  # Kyber768 public key size
        assert len(keypair.secret_key) == 2400  # Kyber768 secret key size
        assert keypair.generated_at > 0

    def test_keypair_generation_kyber512(self):
        engine = CryptoEngine(algorithm="Kyber512", backend="sim")
        keypair = engine.generate_keypair()

        assert len(keypair.public_key) == 800
        assert len(keypair.secret_key) == 1632

    def test_keypair_generation_kyber1024(self):
        engine = CryptoEngine(algorithm="Kyber1024", backend="sim")
        keypair = engine.generate_keypair()

        assert len(keypair.public_key) == 1568
        assert len(keypair.secret_key) == 3168

    def test_encapsulation(self):
        engine = CryptoEngine(algorithm="Kyber768", backend="sim")
        keypair = engine.generate_keypair()

        kem_ct, shared_secret = engine.encapsulate(keypair.public_key)

        assert len(kem_ct) == 1088  # Kyber768 ciphertext size
        assert len(shared_secret) == 32  # SHA-256 output

    def test_shadow_wrap_roundtrip(self):
        """Test that wrapping and unwrapping recovers the original data."""
        engine = CryptoEngine(algorithm="Kyber768", backend="sim")
        plaintext = b"SURREY SATELLITE KEY: SSTL-07-UPLINK-SECRET-DATA"

        wrapped, recovered = engine.wrap_and_unwrap_demo(plaintext)

        assert recovered == plaintext
        assert wrapped.original_size == len(plaintext)
        assert len(wrapped.kem_ciphertext) > 0
        assert len(wrapped.nonce) == 12
        assert len(wrapped.encrypted_payload) > len(plaintext)  # ciphertext + tag

    def test_shadow_wrap_different_data(self):
        """Test wrapping various data sizes."""
        engine = CryptoEngine(backend="sim")

        for size in [1, 16, 256, 1024, 65536]:
            plaintext = os.urandom(size)
            wrapped, recovered = engine.wrap_and_unwrap_demo(plaintext)
            assert recovered == plaintext, f"Failed for size {size}"

    def test_wrapped_packet_serialisation(self):
        """Test that packets can be serialised and deserialised."""
        engine = CryptoEngine(backend="sim")
        plaintext = b"Test data for serialisation"

        wrapped, _ = engine.wrap_and_unwrap_demo(plaintext)

        # Serialise
        wire_bytes = wrapped.to_bytes()
        assert len(wire_bytes) > 0

        # Deserialise
        restored = ShadowWrappedPacket.from_bytes(wire_bytes)
        assert restored.kem_ciphertext == wrapped.kem_ciphertext
        assert restored.nonce == wrapped.nonce
        assert restored.encrypted_payload == wrapped.encrypted_payload

    def test_stats_tracking(self):
        """Test that the engine tracks statistics."""
        engine = CryptoEngine(backend="sim")
        engine.generate_keypair()
        engine.wrap_and_unwrap_demo(b"test")

        stats = engine.stats
        assert stats["keys_generated"] >= 1
        assert stats["packets_wrapped"] >= 1
        assert stats["backend"] == "sim"
        assert stats["algorithm"] == "Kyber768"

    def test_different_wraps_produce_different_output(self):
        """Ensure two wraps of the same data produce different ciphertexts."""
        engine = CryptoEngine(backend="sim")
        plaintext = b"Same data, different wraps"

        wrapped1, _ = engine.wrap_and_unwrap_demo(plaintext)
        wrapped2, _ = engine.wrap_and_unwrap_demo(plaintext)

        # The KEM ciphertexts should differ (different random keys)
        assert wrapped1.kem_ciphertext != wrapped2.kem_ciphertext
        # The AES nonces should differ
        assert wrapped1.nonce != wrapped2.nonce


class TestAlgorithmMapping:
    """Test algorithm name resolution."""

    def test_friendly_names(self):
        engine = CryptoEngine(algorithm="ML-KEM-768", backend="sim")
        assert engine.algorithm == "Kyber768"

    def test_direct_names(self):
        engine = CryptoEngine(algorithm="Kyber512", backend="sim")
        assert engine.algorithm == "Kyber512"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
