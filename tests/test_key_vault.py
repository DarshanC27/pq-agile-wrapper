"""
Tests for the Key Vault.
"""

import os
import sys
import time
import pytest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.config import CryptoConfig, VaultConfig
from src.key_vault import KeyVault


@pytest.fixture(autouse=True)
def init_logger():
    setup_logger(level="WARNING", fmt="plain")


@pytest.fixture
def vault(tmp_path):
    crypto_config = CryptoConfig(
        kem_algorithm="Kyber768",
        symmetric_cipher="AES-256-GCM",
        key_rotation_interval=3600,
    )
    vault_config = VaultConfig(
        storage_path=str(tmp_path / "keys"),
        max_cached_keys=5,
    )
    return KeyVault(crypto_config, vault_config)


class TestKeyVault:
    """Test key generation, storage, rotation, and retrieval."""

    def test_generate_and_store(self, vault):
        entry = vault.generate_and_store()

        assert entry.key_id is not None
        assert len(entry.key_id) == 16
        assert entry.algorithm == "Kyber768"
        assert entry.is_active is True
        assert entry.created_at > 0
        assert entry.expires_at > entry.created_at

    def test_get_active_keypair(self, vault):
        keypair = vault.get_active_keypair()

        assert keypair is not None
        assert keypair.algorithm == "Kyber768"
        assert len(keypair.public_key) == 1184
        assert len(keypair.secret_key) == 2400

    def test_active_keypair_cached(self, vault):
        """Getting active keypair twice should return the same key."""
        kp1 = vault.get_active_keypair()
        kp2 = vault.get_active_keypair()

        assert kp1.public_key == kp2.public_key
        assert kp1.secret_key == kp2.secret_key

    def test_key_lookup_by_id(self, vault):
        entry = vault.generate_and_store()
        sk = vault.get_secret_key(entry.key_id)
        pk = vault.get_public_key(entry.key_id)

        assert sk is not None
        assert pk is not None
        assert len(sk) == 2400
        assert len(pk) == 1184

    def test_key_lookup_nonexistent(self, vault):
        assert vault.get_secret_key("nonexistent") is None
        assert vault.get_public_key("nonexistent") is None

    def test_key_rotation_deactivates_old(self, vault):
        entry1 = vault.generate_and_store()
        entry2 = vault.generate_and_store()

        assert entry1.is_active is False
        assert entry2.is_active is True

    def test_pruning_old_keys(self, vault):
        """Vault should prune when exceeding max_cached_keys."""
        # max_cached_keys = 5
        for _ in range(10):
            vault.generate_and_store()

        assert vault.stats["total_keys"] <= 5

    def test_health_check(self, vault):
        assert vault.is_healthy is False  # No key generated yet

        vault.generate_and_store()
        assert vault.is_healthy is True

    def test_save_and_load(self, vault):
        """Test persistence to disk."""
        vault.generate_and_store()
        keypair_before = vault.get_active_keypair()
        vault.save_to_disk()

        # Create a new vault pointing to the same storage
        crypto_config = CryptoConfig(
            kem_algorithm="Kyber768",
            key_rotation_interval=3600,
        )
        vault_config = VaultConfig(
            storage_path=vault.config.storage_path,
            max_cached_keys=5,
        )
        vault2 = KeyVault(crypto_config, vault_config)
        loaded = vault2.load_from_disk()

        assert loaded is True
        assert vault2.is_healthy is True

    def test_find_by_public_key(self, vault):
        entry = vault.generate_and_store()
        pk = bytes.fromhex(entry.public_key_hex)
        found = vault.find_key_by_public(pk)

        assert found is not None
        assert found.key_id == entry.key_id

    def test_stats(self, vault):
        vault.generate_and_store()
        stats = vault.stats

        assert stats["total_keys"] == 1
        assert stats["active_key_id"] is not None
        assert stats["is_healthy"] is True


class TestKeyVaultExpiration:
    """Test key expiration and auto-rotation."""

    def test_expired_key_triggers_rotation(self, tmp_path):
        crypto_config = CryptoConfig(
            kem_algorithm="Kyber768",
            key_rotation_interval=1,  # 1 second rotation
        )
        vault_config = VaultConfig(
            storage_path=str(tmp_path / "keys"),
            max_cached_keys=10,
        )
        vault = KeyVault(crypto_config, vault_config)

        kp1 = vault.get_active_keypair()
        time.sleep(1.1)  # Wait for expiration
        kp2 = vault.get_active_keypair()

        # Should have rotated to a new key
        assert kp1.public_key != kp2.public_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
