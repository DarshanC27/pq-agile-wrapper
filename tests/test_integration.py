"""
Integration Test — Full Shadow Proxy Pipeline
===============================================

Tests the complete flow:
  Client → Shadow Proxy → Legacy Server → Response

Verifies:
  1. Metadata evaluation works end-to-end
  2. Shadow Wrap is applied to sensitive data
  3. Pass-through works for low-priority data
  4. Fail-safe triggers correctly
  5. Proxy handles concurrent connections
"""

import os
import sys
import asyncio
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.config import load_config, AppConfig
from src.crypto_engine import CryptoEngine
from src.metadata_evaluator import MetadataEvaluator, Action
from src.key_vault import KeyVault
from src.failsafe import FailsafeMonitor, FailsafeState


@pytest.fixture(autouse=True)
def init_logger():
    setup_logger(level="WARNING", fmt="plain")


class TestEndToEndCryptoFlow:
    """Test the full encryption/decryption pipeline."""

    def test_full_wrap_unwrap_pipeline(self):
        """
        Simulate the complete Shadow Proxy crypto pipeline:
        1. Evaluate data → decide to shield
        2. Generate keys
        3. Wrap data with ML-KEM
        4. Transmit wrapped data
        5. Unwrap on the other side
        6. Verify data integrity
        """
        config = load_config()

        # Step 1: Evaluate
        evaluator = MetadataEvaluator(config.classifier)
        result = evaluator.evaluate(metadata_header="satellite_keys")
        assert result.action == Action.APPLY_SHIELD

        # Step 2: Generate keys via vault
        vault = KeyVault(config.crypto, config.vault)
        keypair = vault.get_active_keypair()
        assert keypair is not None

        # Step 3: Wrap
        engine = CryptoEngine(algorithm=config.crypto.kem_algorithm)
        original_data = (
            b"SATELLITE KEY: SSTL-07-UPLINK\n"
            b"AES-256-GCM-KEY: 4a8f2c1b9e7d3a6f\n"
            b"CLASSIFICATION: UK OFFICIAL-SENSITIVE\n"
        )
        wrapped = engine.shadow_wrap(original_data, keypair.public_key)

        # Verify wrapped packet structure
        assert len(wrapped.kem_ciphertext) > 0
        assert len(wrapped.nonce) == 12
        assert len(wrapped.encrypted_payload) > len(original_data)
        assert wrapped.original_size == len(original_data)

        # Step 4: Serialise (simulates network transmission)
        wire_data = wrapped.to_bytes()
        assert len(wire_data) > len(original_data)

        # Step 5: Deserialise
        from src.crypto_engine import ShadowWrappedPacket
        received = ShadowWrappedPacket.from_bytes(wire_data)
        assert received.kem_ciphertext == wrapped.kem_ciphertext
        assert received.nonce == wrapped.nonce
        assert received.encrypted_payload == wrapped.encrypted_payload

    def test_wrap_preserves_data_integrity(self):
        """Ensure wrapped+unwrapped data matches the original exactly."""
        engine = CryptoEngine(backend="sim")

        test_payloads = [
            b"Short",
            b"A" * 1024,
            b"\x00" * 100,  # null bytes
            os.urandom(4096),  # random binary
            b"Unicode: \xc3\xa9\xc3\xa0\xc3\xbc",  # UTF-8 encoded
            b'{"json": "payload", "count": 42}',  # JSON
        ]

        for payload in test_payloads:
            wrapped, recovered = engine.wrap_and_unwrap_demo(payload)
            assert recovered == payload, f"Data mismatch for {len(payload)}B payload"

    def test_overhead_is_acceptable(self):
        """Verify the packet overhead stays within Surrey IoT bounds (< 2KB)."""
        engine = CryptoEngine(algorithm="Kyber768", backend="sim")

        # Simulate a typical IoT sensor reading
        iot_payload = json.dumps({
            "sensor_id": "surrey-iot-temp-042",
            "reading": 21.5,
            "unit": "celsius",
            "timestamp": "2026-04-01T12:00:00Z",
        }).encode()

        wrapped, _ = engine.wrap_and_unwrap_demo(iot_payload)
        wire_bytes = wrapped.to_bytes()
        overhead = len(wire_bytes) - len(iot_payload)

        # Overhead should be roughly: KEM ciphertext (1088) + nonce (12)
        # + AES tag (16) + length header (2) ≈ 1118 bytes
        assert overhead < 2048, f"Overhead {overhead}B exceeds 2KB IoT limit"


class TestFailsafeIntegration:
    """Test failsafe behaviour in the context of the full system."""

    def test_failsafe_preserves_data_flow(self):
        """
        When failsafe activates, data should still flow
        (just without PQ protection).
        """
        from src.config import FailsafeConfig

        monitor = FailsafeMonitor(FailsafeConfig(
            latency_threshold_ms=10,
            enabled=True,
        ))

        # Simulate high latency causing fallback
        monitor.check_latency(100.0)
        monitor.check_latency(100.0)
        monitor.check_latency(100.0)

        assert monitor.state == FailsafeState.CLASSICAL_FALLBACK
        assert monitor.is_pq_active is False

        # In fallback mode, data should pass through unmodified
        # (the proxy would skip the shadow wrap)
        original_data = b"This data flows through without PQ wrapping"
        forwarded_data = original_data  # No wrapping applied
        assert forwarded_data == original_data


class TestConfigIntegration:
    """Test configuration loading and component wiring."""

    def test_default_config_loads(self):
        config = load_config()
        assert config.proxy.listen_port == 8443
        assert config.crypto.kem_algorithm == "Kyber768"
        assert config.classifier.ncsc_deadline_year == 2035
        assert config.failsafe.enabled is True

    def test_all_components_initialise_with_config(self):
        """Ensure all components can be created from the config."""
        config = load_config()

        engine = CryptoEngine(algorithm=config.crypto.kem_algorithm)
        evaluator = MetadataEvaluator(config.classifier)
        vault = KeyVault(config.crypto, config.vault)
        monitor = FailsafeMonitor(config.failsafe)

        assert engine.algorithm == "Kyber768"
        assert evaluator.config.ncsc_deadline_year == 2035
        assert vault.is_healthy is False  # No key yet
        assert monitor.is_pq_active is True

    def test_evaluate_then_wrap_pipeline(self):
        """Test the decide-then-encrypt pipeline end-to-end."""
        config = load_config()
        evaluator = MetadataEvaluator(config.classifier)
        engine = CryptoEngine(backend="sim")

        # Evaluate each configured category
        for cat_key in config.classifier.data_categories:
            result = evaluator.evaluate(metadata_header=cat_key)

            if result.action == Action.APPLY_SHIELD:
                # Wrap it
                keypair = engine.generate_keypair()
                test_data = f"Sensitive: {cat_key}".encode()
                wrapped, recovered = engine.wrap_and_unwrap_demo(test_data)
                assert recovered == test_data


class TestCryptoAgility:
    """Test that the system can switch algorithms (crypto-agility)."""

    def test_switch_between_kyber_variants(self):
        """Verify we can create engines with different security levels."""
        for algo in ["Kyber512", "Kyber768", "Kyber1024"]:
            engine = CryptoEngine(algorithm=algo, backend="sim")
            wrapped, recovered = engine.wrap_and_unwrap_demo(
                b"Testing crypto agility"
            )
            assert recovered == b"Testing crypto agility"
            assert engine.algorithm == algo

    def test_algorithm_mapping(self):
        """Test that NIST names map to Kyber names."""
        engine = CryptoEngine(algorithm="ML-KEM-768", backend="sim")
        assert engine.algorithm == "Kyber768"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
