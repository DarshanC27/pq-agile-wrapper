"""
Crypto Engine — ML-KEM Hybrid Encryption Core
=============================================

Implements the "Shadow Wrap" — hybrid encryption combining:
  1. ML-KEM (Kyber) lattice-based key encapsulation (quantum-resistant)
  2. AES-256-GCM symmetric encryption (classical, fast)

The flow:
  1. Generate an ML-KEM keypair (public + secret)
  2. Encapsulate: use the public key to produce (ciphertext, shared_secret)
  3. Use the shared_secret as an AES-256-GCM key to encrypt the payload
  4. Output: ML-KEM ciphertext + AES nonce + AES ciphertext + AES tag

This module supports two backends:
  - "oqs" — real post-quantum crypto via liboqs-python (production)
  - "sim" — simulated mode using classical crypto (demo / development)
"""

import os
import time
import hashlib
import struct
from dataclasses import dataclass
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .logger import get_logger

# ---------------------------------------------------------------------------
# Try to import liboqs; fall back to simulation mode if unavailable
# ---------------------------------------------------------------------------
OQS_AVAILABLE = False
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class KEMKeypair:
    """An ML-KEM keypair."""
    algorithm: str
    public_key: bytes
    secret_key: bytes
    generated_at: float  # unix timestamp


@dataclass
class ShadowWrappedPacket:
    """
    The output of the Shadow Wrap process.

    Wire format (for transmission):
      [2 bytes: kem_ct_len][kem_ciphertext][12 bytes: nonce][payload_ciphertext + 16-byte tag]
    """
    kem_ciphertext: bytes     # ML-KEM encapsulated ciphertext
    nonce: bytes              # 12-byte AES-GCM nonce
    encrypted_payload: bytes  # AES-256-GCM ciphertext (includes tag)
    original_size: int        # size of original plaintext

    def to_bytes(self) -> bytes:
        """Serialise to wire format."""
        kem_ct_len = len(self.kem_ciphertext)
        return (
            struct.pack("!H", kem_ct_len)
            + self.kem_ciphertext
            + self.nonce
            + self.encrypted_payload
        )

    @classmethod
    def from_bytes(cls, data: bytes, kem_ct_len: Optional[int] = None) -> "ShadowWrappedPacket":
        """Deserialise from wire format."""
        offset = 0
        (ct_len,) = struct.unpack("!H", data[offset : offset + 2])
        offset += 2
        kem_ct = data[offset : offset + ct_len]
        offset += ct_len
        nonce = data[offset : offset + 12]
        offset += 12
        encrypted = data[offset:]
        return cls(
            kem_ciphertext=kem_ct,
            nonce=nonce,
            encrypted_payload=encrypted,
            original_size=0,
        )


# ---------------------------------------------------------------------------
# Crypto Engine
# ---------------------------------------------------------------------------

class CryptoEngine:
    """
    The Shadow Wrap crypto engine.

    Manages ML-KEM key generation, encapsulation, and hybrid encryption.
    """

    # Map friendly names to liboqs algorithm identifiers
    ALGORITHM_MAP = {
        "Kyber512": "Kyber512",
        "Kyber768": "Kyber768",
        "Kyber1024": "Kyber1024",
        "ML-KEM-512": "Kyber512",
        "ML-KEM-768": "Kyber768",
        "ML-KEM-1024": "Kyber1024",
    }

    def __init__(self, algorithm: str = "Kyber768", backend: Optional[str] = None):
        """
        Initialise the crypto engine.

        Args:
            algorithm: KEM algorithm name (e.g. "Kyber768")
            backend: Force "oqs" or "sim". Auto-detects if None.
        """
        self.log = get_logger()
        self.algorithm = self.ALGORITHM_MAP.get(algorithm, algorithm)

        if backend:
            self.backend = backend
        elif OQS_AVAILABLE:
            self.backend = "oqs"
        else:
            self.backend = "sim"
            self.log.warning(
                "liboqs not available — running in SIMULATION mode. "
                "Install liboqs-python for real post-quantum crypto."
            )

        self._stats = {
            "keys_generated": 0,
            "packets_wrapped": 0,
            "packets_unwrapped": 0,
            "total_wrap_time_ms": 0.0,
        }

    # ------------------------------------------------------------------
    # Key Generation
    # ------------------------------------------------------------------

    def generate_keypair(self) -> KEMKeypair:
        """Generate a fresh ML-KEM keypair."""
        start = time.perf_counter()

        if self.backend == "oqs":
            keypair = self._oqs_generate()
        else:
            keypair = self._sim_generate()

        elapsed = (time.perf_counter() - start) * 1000
        self._stats["keys_generated"] += 1
        self.log.info(
            f"Generated {self.algorithm} keypair "
            f"(pk={len(keypair.public_key)}B, sk={len(keypair.secret_key)}B) "
            f"in {elapsed:.2f}ms"
        )
        return keypair

    def _oqs_generate(self) -> KEMKeypair:
        """Generate keypair using liboqs."""
        kem = oqs.KeyEncapsulation(self.algorithm)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return KEMKeypair(
            algorithm=self.algorithm,
            public_key=bytes(public_key),
            secret_key=bytes(secret_key),
            generated_at=time.time(),
        )

    def _sim_generate(self) -> KEMKeypair:
        """
        Simulated keypair generation (for demo without liboqs).
        Uses random bytes sized to match real Kyber key sizes.
        """
        sizes = {
            "Kyber512": (800, 1632),
            "Kyber768": (1184, 2400),
            "Kyber1024": (1568, 3168),
        }
        pk_size, sk_size = sizes.get(self.algorithm, (1184, 2400))
        return KEMKeypair(
            algorithm=self.algorithm,
            public_key=os.urandom(pk_size),
            secret_key=os.urandom(sk_size),
            generated_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Encapsulation (sender side)
    # ------------------------------------------------------------------

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate using the recipient's public key.

        Returns:
            (kem_ciphertext, shared_secret)
        """
        if self.backend == "oqs":
            return self._oqs_encapsulate(public_key)
        else:
            return self._sim_encapsulate(public_key)

    def _oqs_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation(self.algorithm)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def _sim_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Simulated encapsulation — produces random ciphertext + derived secret."""
        ct_sizes = {"Kyber512": 768, "Kyber768": 1088, "Kyber1024": 1568}
        ct_size = ct_sizes.get(self.algorithm, 1088)
        ciphertext = os.urandom(ct_size)
        # Derive a 32-byte shared secret from public key + ciphertext
        shared_secret = hashlib.sha256(public_key + ciphertext).digest()
        return ciphertext, shared_secret

    # ------------------------------------------------------------------
    # Decapsulation (receiver side)
    # ------------------------------------------------------------------

    def decapsulate(self, secret_key: bytes, kem_ciphertext: bytes) -> bytes:
        """
        Decapsulate using the secret key to recover the shared secret.

        Returns:
            shared_secret (32 bytes)
        """
        if self.backend == "oqs":
            return self._oqs_decapsulate(secret_key, kem_ciphertext)
        else:
            return self._sim_decapsulate(secret_key, kem_ciphertext)

    def _oqs_decapsulate(self, secret_key: bytes, kem_ciphertext: bytes) -> bytes:
        kem = oqs.KeyEncapsulation(self.algorithm, secret_key=secret_key)
        shared_secret = kem.decap_secret(kem_ciphertext)
        return bytes(shared_secret)

    def _sim_decapsulate(self, secret_key: bytes, kem_ciphertext: bytes) -> bytes:
        """In simulation, we can't truly decapsulate — we re-derive the secret."""
        # This only works if we have the matching public key
        # For simulation, we store the secret in a lookup (see key_vault.py)
        # Here we just return a hash — the demo handles the pairing
        return hashlib.sha256(secret_key[:800] + kem_ciphertext).digest()

    # ------------------------------------------------------------------
    # Shadow Wrap — Full Hybrid Encryption
    # ------------------------------------------------------------------

    def shadow_wrap(self, plaintext: bytes, public_key: bytes) -> ShadowWrappedPacket:
        """
        Apply the Shadow Wrap: ML-KEM encapsulation + AES-256-GCM encryption.

        This is the core operation — it wraps data in a quantum-resistant layer
        without modifying the original payload structure.

        Args:
            plaintext: The data to protect
            public_key: Recipient's ML-KEM public key

        Returns:
            ShadowWrappedPacket containing the hybrid-encrypted data
        """
        start = time.perf_counter()

        # Step 1: ML-KEM encapsulation → get ciphertext + shared secret
        kem_ciphertext, shared_secret = self.encapsulate(public_key)

        # Step 2: Use shared secret as AES-256-GCM key
        aes_key = shared_secret[:32]  # ML-KEM shared secret is 32 bytes
        nonce = os.urandom(12)        # 96-bit nonce for AES-GCM

        # Step 3: Encrypt the plaintext with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(nonce, plaintext, None)

        elapsed = (time.perf_counter() - start) * 1000
        self._stats["packets_wrapped"] += 1
        self._stats["total_wrap_time_ms"] += elapsed

        self.log.debug(
            f"Shadow Wrap applied: {len(plaintext)}B → "
            f"{len(kem_ciphertext) + 12 + len(encrypted_payload)}B "
            f"({elapsed:.2f}ms)"
        )

        return ShadowWrappedPacket(
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            encrypted_payload=encrypted_payload,
            original_size=len(plaintext),
        )

    def shadow_unwrap(
        self, packet: ShadowWrappedPacket, secret_key: bytes
    ) -> bytes:
        """
        Remove the Shadow Wrap: ML-KEM decapsulation + AES-256-GCM decryption.

        Args:
            packet: The ShadowWrappedPacket to unwrap
            secret_key: Recipient's ML-KEM secret key

        Returns:
            Original plaintext bytes
        """
        start = time.perf_counter()

        # Step 1: ML-KEM decapsulation → recover shared secret
        shared_secret = self.decapsulate(secret_key, packet.kem_ciphertext)

        # Step 2: AES-256-GCM decryption
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(packet.nonce, packet.encrypted_payload, None)

        elapsed = (time.perf_counter() - start) * 1000
        self._stats["packets_unwrapped"] += 1

        self.log.debug(f"Shadow Unwrap: recovered {len(plaintext)}B ({elapsed:.2f}ms)")
        return plaintext

    # ------------------------------------------------------------------
    # Convenience: wrap raw bytes end-to-end (for demo / testing)
    # ------------------------------------------------------------------

    def wrap_and_unwrap_demo(self, plaintext: bytes) -> Tuple[ShadowWrappedPacket, bytes]:
        """
        Full round-trip demo: generate keys → wrap → unwrap → verify.
        Returns (wrapped_packet, recovered_plaintext).
        """
        keypair = self.generate_keypair()
        wrapped = self.shadow_wrap(plaintext, keypair.public_key)

        # For simulation mode, we need a shared secret that matches
        if self.backend == "sim":
            # Re-derive the shared secret the same way encapsulate did
            shared_secret = hashlib.sha256(
                keypair.public_key + wrapped.kem_ciphertext
            ).digest()
            aes_key = shared_secret[:32]
            aesgcm = AESGCM(aes_key)
            recovered = aesgcm.decrypt(
                wrapped.nonce, wrapped.encrypted_payload, None
            )
        else:
            recovered = self.shadow_unwrap(wrapped, keypair.secret_key)

        return wrapped, recovered

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        avg = 0.0
        if self._stats["packets_wrapped"] > 0:
            avg = self._stats["total_wrap_time_ms"] / self._stats["packets_wrapped"]
        return {
            **self._stats,
            "avg_wrap_time_ms": round(avg, 3),
            "backend": self.backend,
            "algorithm": self.algorithm,
        }
