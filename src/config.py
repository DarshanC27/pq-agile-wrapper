"""
Configuration loader for the Shadow Proxy.
Reads YAML config and provides typed access to settings.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Optional
from pathlib import Path


@dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    forward_host: str = "127.0.0.1"
    forward_port: int = 8080
    buffer_size: int = 65536
    max_connections: int = 100


@dataclass
class CryptoConfig:
    kem_algorithm: str = "Kyber768"
    symmetric_cipher: str = "AES-256-GCM"
    key_rotation_interval: int = 3600


@dataclass
class DataCategory:
    label: str
    shelf_life_years: int
    priority: str  # "critical" | "high" | "medium" | "low"


@dataclass
class ClassifierConfig:
    ncsc_deadline_year: int = 2035
    data_categories: Dict[str, DataCategory] = field(default_factory=dict)
    metadata_header: str = "X-PQ-Data-Class"
    default_action: str = "apply_shield"


@dataclass
class FailsafeConfig:
    latency_threshold_ms: int = 50
    vault_timeout_ms: int = 2000
    alert_webhook: str = ""
    enabled: bool = True


@dataclass
class VaultConfig:
    storage_path: str = "./data/keys"
    max_cached_keys: int = 50


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "structured"
    log_file: str = "./logs/shadow_proxy.log"


@dataclass
class AppConfig:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    classifier: ClassifierConfig = field(default_factory=ClassifierConfig)
    failsafe: FailsafeConfig = field(default_factory=FailsafeConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file, with environment variable overrides."""

    if config_path is None:
        config_path = os.environ.get(
            "PQ_CONFIG_PATH",
            str(Path(__file__).parent.parent / "config" / "default.yaml"),
        )

    config_path = Path(config_path)
    if not config_path.exists():
        print(f"[CONFIG] No config file at {config_path}, using defaults.")
        return AppConfig()

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    app = AppConfig()

    # --- Proxy ---
    if "proxy" in raw:
        p = raw["proxy"]
        app.proxy = ProxyConfig(
            listen_host=p.get("listen_host", app.proxy.listen_host),
            listen_port=int(p.get("listen_port", app.proxy.listen_port)),
            forward_host=p.get("forward_host", app.proxy.forward_host),
            forward_port=int(p.get("forward_port", app.proxy.forward_port)),
            buffer_size=int(p.get("buffer_size", app.proxy.buffer_size)),
            max_connections=int(p.get("max_connections", app.proxy.max_connections)),
        )

    # --- Crypto ---
    if "crypto" in raw:
        c = raw["crypto"]
        app.crypto = CryptoConfig(
            kem_algorithm=c.get("kem_algorithm", app.crypto.kem_algorithm),
            symmetric_cipher=c.get("symmetric_cipher", app.crypto.symmetric_cipher),
            key_rotation_interval=int(
                c.get("key_rotation_interval", app.crypto.key_rotation_interval)
            ),
        )

    # --- Classifier ---
    if "classifier" in raw:
        cl = raw["classifier"]
        categories = {}
        for key, val in cl.get("data_categories", {}).items():
            categories[key] = DataCategory(
                label=val.get("label", key),
                shelf_life_years=int(val.get("shelf_life_years", 10)),
                priority=val.get("priority", "medium"),
            )
        app.classifier = ClassifierConfig(
            ncsc_deadline_year=int(
                cl.get("ncsc_deadline_year", app.classifier.ncsc_deadline_year)
            ),
            data_categories=categories,
            metadata_header=cl.get(
                "metadata_header", app.classifier.metadata_header
            ),
            default_action=cl.get("default_action", app.classifier.default_action),
        )

    # --- Failsafe ---
    if "failsafe" in raw:
        fs = raw["failsafe"]
        app.failsafe = FailsafeConfig(
            latency_threshold_ms=int(
                fs.get("latency_threshold_ms", app.failsafe.latency_threshold_ms)
            ),
            vault_timeout_ms=int(
                fs.get("vault_timeout_ms", app.failsafe.vault_timeout_ms)
            ),
            alert_webhook=fs.get("alert_webhook", app.failsafe.alert_webhook),
            enabled=bool(fs.get("enabled", app.failsafe.enabled)),
        )

    # --- Vault ---
    if "vault" in raw:
        v = raw["vault"]
        app.vault = VaultConfig(
            storage_path=v.get("storage_path", app.vault.storage_path),
            max_cached_keys=int(
                v.get("max_cached_keys", app.vault.max_cached_keys)
            ),
        )

    # --- Logging ---
    if "logging" in raw:
        lg = raw["logging"]
        app.logging = LoggingConfig(
            level=lg.get("level", app.logging.level),
            format=lg.get("format", app.logging.format),
            log_file=lg.get("log_file", app.logging.log_file),
        )

    # --- Environment variable overrides ---
    if os.environ.get("PQ_LISTEN_PORT"):
        app.proxy.listen_port = int(os.environ["PQ_LISTEN_PORT"])
    if os.environ.get("PQ_FORWARD_PORT"):
        app.proxy.forward_port = int(os.environ["PQ_FORWARD_PORT"])
    if os.environ.get("PQ_KEM_ALGORITHM"):
        app.crypto.kem_algorithm = os.environ["PQ_KEM_ALGORITHM"]
    if os.environ.get("PQ_LOG_LEVEL"):
        app.logging.level = os.environ["PQ_LOG_LEVEL"]

    return app
