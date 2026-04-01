"""
Key Vault — ML-KEM Key Management
==================================

Manages the lifecycle of ML-KEM keypairs:
  - Generation and caching
  - Time-based rotation
  - Secure storage
  - Key lookup for decapsulation
"""

import os
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass, asdict

from .crypto_engine import CryptoEngine, KEMKeypair
from .config import VaultConfig, CryptoConfig
from .logger import get_logger


@dataclass
class VaultEntry:
    """A stored keypair with metadata."""
    key_id: str
    algorithm: str
    public_key_hex: str
    secret_key_hex: str
    created_at: float
    expires_at: float
    is_active: bool = True


class KeyVault:
    """
    Secure key vault for ML-KEM keypairs.

    Handles key generation, caching, rotation, and lookup.
    In production, this would integrate with an HSM or cloud KMS.
    For the prototype, keys are stored in memory and optionally on disk.
    """

    def __init__(
        self,
        crypto_config: CryptoConfig,
        vault_config: VaultConfig,
    ):
        self.log = get_logger()
        self.crypto = CryptoEngine(
            algorithm=crypto_config.kem_algorithm,
        )
        self.config = vault_config
        self.rotation_interval = crypto_config.key_rotation_interval

        # In-memory key store
        self._keys: Dict[str, VaultEntry] = {}
        self._active_key_id: Optional[str] = None

        # Ensure storage directory exists
        self.storage_path = Path(self.config.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.log.info(
            f"Key Vault initialised (algorithm={crypto_config.kem_algorithm}, "
            f"rotation={self.rotation_interval}s)"
        )

    def _generate_key_id(self, public_key: bytes) -> str:
        """Generate a unique key ID from the public key hash."""
        return hashlib.sha256(public_key).hexdigest()[:16]

    def generate_and_store(self) -> VaultEntry:
        """Generate a new ML-KEM keypair and store it in the vault."""
        keypair = self.crypto.generate_keypair()
        key_id = self._generate_key_id(keypair.public_key)

        entry = VaultEntry(
            key_id=key_id,
            algorithm=keypair.algorithm,
            public_key_hex=keypair.public_key.hex(),
            secret_key_hex=keypair.secret_key.hex(),
            created_at=time.time(),
            expires_at=time.time() + self.rotation_interval,
            is_active=True,
        )

        # Deactivate old active key
        if self._active_key_id and self._active_key_id in self._keys:
            self._keys[self._active_key_id].is_active = False

        self._keys[key_id] = entry
        self._active_key_id = key_id

        # Prune old keys if over limit
        self._prune_old_keys()

        self.log.info(f"Stored new key {key_id} (expires in {self.rotation_interval}s)")
        return entry

    def get_active_keypair(self) -> Optional[KEMKeypair]:
        """
        Get the current active keypair, generating a new one if needed.
        Handles automatic rotation.
        """
        if self._active_key_id:
            entry = self._keys.get(self._active_key_id)
            if entry and entry.is_active and time.time() < entry.expires_at:
                return KEMKeypair(
                    algorithm=entry.algorithm,
                    public_key=bytes.fromhex(entry.public_key_hex),
                    secret_key=bytes.fromhex(entry.secret_key_hex),
                    generated_at=entry.created_at,
                )
            else:
                self.log.info("Active key expired — rotating.")

        # Generate a fresh keypair
        entry = self.generate_and_store()
        return KEMKeypair(
            algorithm=entry.algorithm,
            public_key=bytes.fromhex(entry.public_key_hex),
            secret_key=bytes.fromhex(entry.secret_key_hex),
            generated_at=entry.created_at,
        )

    def get_secret_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a secret key by ID (for decapsulation)."""
        entry = self._keys.get(key_id)
        if entry:
            return bytes.fromhex(entry.secret_key_hex)
        return None

    def get_public_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a public key by ID."""
        entry = self._keys.get(key_id)
        if entry:
            return bytes.fromhex(entry.public_key_hex)
        return None

    def find_key_by_public(self, public_key: bytes) -> Optional[VaultEntry]:
        """Find a vault entry by its public key."""
        key_id = self._generate_key_id(public_key)
        return self._keys.get(key_id)

    def _prune_old_keys(self):
        """Remove oldest inactive keys if over the cache limit."""
        if len(self._keys) <= self.config.max_cached_keys:
            return

        # Sort by creation time, remove oldest inactive ones
        inactive = [
            (kid, entry)
            for kid, entry in self._keys.items()
            if not entry.is_active
        ]
        inactive.sort(key=lambda x: x[1].created_at)

        while len(self._keys) > self.config.max_cached_keys and inactive:
            kid, _ = inactive.pop(0)
            del self._keys[kid]
            self.log.debug(f"Pruned old key {kid}")

    def save_to_disk(self):
        """Persist the key vault to disk (JSON). For prototype only."""
        vault_file = self.storage_path / "vault.json"
        data = {
            kid: asdict(entry)
            for kid, entry in self._keys.items()
        }
        with open(vault_file, "w") as f:
            json.dump(data, f, indent=2)
        self.log.debug(f"Vault saved to {vault_file}")

    def load_from_disk(self) -> bool:
        """Load the key vault from disk. Returns True if successful."""
        vault_file = self.storage_path / "vault.json"
        if not vault_file.exists():
            return False

        try:
            with open(vault_file, "r") as f:
                data = json.load(f)
            for kid, entry_data in data.items():
                self._keys[kid] = VaultEntry(**entry_data)
                if entry_data.get("is_active"):
                    self._active_key_id = kid
            self.log.info(f"Loaded {len(self._keys)} keys from disk")
            return True
        except Exception as e:
            self.log.error(f"Failed to load vault: {e}")
            return False

    @property
    def is_healthy(self) -> bool:
        """Check if the vault has an active, non-expired key."""
        if not self._active_key_id:
            return False
        entry = self._keys.get(self._active_key_id)
        return entry is not None and entry.is_active and time.time() < entry.expires_at

    @property
    def stats(self) -> dict:
        return {
            "total_keys": len(self._keys),
            "active_key_id": self._active_key_id,
            "is_healthy": self.is_healthy,
        }
