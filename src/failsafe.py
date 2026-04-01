"""
Fail-Safe Monitor
=================

Ensures the Shadow Proxy degrades gracefully:
  - If PQ handshake latency exceeds threshold → fall back to classical
  - If Key Vault is unreachable → fall back to classical + fire alert
  - All fallbacks log a high-priority warning

This is critical for production reliability — the proxy must NEVER
block traffic, even if the quantum layer has issues.
"""

import time
import json
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum

from .config import FailsafeConfig
from .logger import get_logger


class FailsafeState(Enum):
    NORMAL = "normal"               # PQ layer is active and healthy
    DEGRADED = "degraded"           # PQ layer has issues, still trying
    CLASSICAL_FALLBACK = "fallback" # Reverted to classical-only


@dataclass
class FailsafeEvent:
    """A failsafe event for logging and alerting."""
    state: FailsafeState
    reason: str
    timestamp: float
    latency_ms: Optional[float] = None
    vault_reachable: bool = True


class FailsafeMonitor:
    """
    Monitors the health of the PQ layer and triggers fallback if needed.
    """

    def __init__(self, config: FailsafeConfig):
        self.config = config
        self.log = get_logger()
        self.state = FailsafeState.NORMAL
        self._events: list = []
        self._alert_callback: Optional[Callable] = None
        self._consecutive_failures = 0
        self._max_failures_before_fallback = 3

    def set_alert_callback(self, callback: Callable[[FailsafeEvent], None]):
        """Register a callback for failsafe alerts (webhook, email, etc.)."""
        self._alert_callback = callback

    def check_latency(self, operation_ms: float) -> FailsafeState:
        """
        Check if a PQ operation's latency is within acceptable bounds.

        Args:
            operation_ms: Time taken for the PQ operation in milliseconds

        Returns:
            Current FailsafeState
        """
        if not self.config.enabled:
            return FailsafeState.NORMAL

        if operation_ms > self.config.latency_threshold_ms:
            self._consecutive_failures += 1
            self.log.warning(
                f"PQ operation took {operation_ms:.1f}ms "
                f"(threshold: {self.config.latency_threshold_ms}ms) "
                f"[{self._consecutive_failures}/{self._max_failures_before_fallback}]"
            )

            if self._consecutive_failures >= self._max_failures_before_fallback:
                self._trigger_fallback(
                    f"PQ latency exceeded {self.config.latency_threshold_ms}ms "
                    f"for {self._consecutive_failures} consecutive operations",
                    latency_ms=operation_ms,
                )
            else:
                self.state = FailsafeState.DEGRADED
        else:
            # Reset failure counter on success
            if self._consecutive_failures > 0:
                self._consecutive_failures = 0
                if self.state == FailsafeState.DEGRADED:
                    self.state = FailsafeState.NORMAL
                    self.log.info("PQ layer recovered — back to normal operation.")

        return self.state

    def check_vault_health(self, is_reachable: bool) -> FailsafeState:
        """
        Check if the Key Vault is reachable.

        Args:
            is_reachable: Whether the vault responded within timeout

        Returns:
            Current FailsafeState
        """
        if not self.config.enabled:
            return FailsafeState.NORMAL

        if not is_reachable:
            self._trigger_fallback(
                "Key Vault is unreachable — cannot generate PQ keys",
                vault_reachable=False,
            )
        elif self.state == FailsafeState.CLASSICAL_FALLBACK:
            # Vault recovered
            self.state = FailsafeState.NORMAL
            self._consecutive_failures = 0
            self.log.info("Key Vault recovered — PQ layer re-enabled.")

        return self.state

    def _trigger_fallback(
        self,
        reason: str,
        latency_ms: Optional[float] = None,
        vault_reachable: bool = True,
    ):
        """Switch to classical-only fallback and fire alerts."""
        self.state = FailsafeState.CLASSICAL_FALLBACK

        event = FailsafeEvent(
            state=self.state,
            reason=reason,
            timestamp=time.time(),
            latency_ms=latency_ms,
            vault_reachable=vault_reachable,
        )
        self._events.append(event)

        self.log.critical(
            f"FAILSAFE ACTIVATED: Reverting to classical encryption. "
            f"Reason: {reason}"
        )

        # Fire alert callback if registered
        if self._alert_callback:
            try:
                self._alert_callback(event)
            except Exception as e:
                self.log.error(f"Alert callback failed: {e}")

    def force_recovery(self):
        """Manually reset the failsafe state (admin action)."""
        self.state = FailsafeState.NORMAL
        self._consecutive_failures = 0
        self.log.info("Failsafe manually reset by administrator.")

    @property
    def is_pq_active(self) -> bool:
        """Whether the PQ layer is currently active."""
        return self.state != FailsafeState.CLASSICAL_FALLBACK

    @property
    def stats(self) -> dict:
        return {
            "state": self.state.value,
            "is_pq_active": self.is_pq_active,
            "consecutive_failures": self._consecutive_failures,
            "total_failsafe_events": len(self._events),
        }
