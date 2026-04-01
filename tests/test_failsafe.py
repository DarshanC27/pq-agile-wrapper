"""
Tests for the Fail-Safe Monitor.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.config import FailsafeConfig
from src.failsafe import FailsafeMonitor, FailsafeState


@pytest.fixture(autouse=True)
def init_logger():
    setup_logger(level="WARNING", fmt="plain")


@pytest.fixture
def monitor():
    config = FailsafeConfig(
        latency_threshold_ms=50,
        vault_timeout_ms=2000,
        alert_webhook="",
        enabled=True,
    )
    return FailsafeMonitor(config)


class TestFailsafeMonitor:
    """Test fail-safe fallback logic."""

    def test_initial_state_normal(self, monitor):
        assert monitor.state == FailsafeState.NORMAL
        assert monitor.is_pq_active is True

    def test_normal_latency(self, monitor):
        state = monitor.check_latency(10.0)  # 10ms — well within 50ms threshold
        assert state == FailsafeState.NORMAL
        assert monitor.is_pq_active is True

    def test_single_high_latency_degrades(self, monitor):
        state = monitor.check_latency(100.0)  # Over threshold
        assert state == FailsafeState.DEGRADED

    def test_consecutive_failures_trigger_fallback(self, monitor):
        """3 consecutive high-latency operations should trigger fallback."""
        monitor.check_latency(100.0)
        monitor.check_latency(100.0)
        state = monitor.check_latency(100.0)  # Third failure

        assert state == FailsafeState.CLASSICAL_FALLBACK
        assert monitor.is_pq_active is False

    def test_recovery_after_success(self, monitor):
        """A successful operation should reset the failure counter."""
        monitor.check_latency(100.0)
        monitor.check_latency(100.0)
        # Now a good one — should recover
        state = monitor.check_latency(10.0)

        assert state == FailsafeState.NORMAL
        assert monitor.is_pq_active is True

    def test_vault_unreachable_triggers_fallback(self, monitor):
        state = monitor.check_vault_health(is_reachable=False)

        assert state == FailsafeState.CLASSICAL_FALLBACK
        assert monitor.is_pq_active is False

    def test_vault_recovery(self, monitor):
        monitor.check_vault_health(is_reachable=False)
        assert monitor.is_pq_active is False

        state = monitor.check_vault_health(is_reachable=True)
        assert state == FailsafeState.NORMAL
        assert monitor.is_pq_active is True

    def test_force_recovery(self, monitor):
        """Admin manual reset should work."""
        monitor.check_vault_health(is_reachable=False)
        assert monitor.is_pq_active is False

        monitor.force_recovery()
        assert monitor.state == FailsafeState.NORMAL
        assert monitor.is_pq_active is True

    def test_alert_callback(self, monitor):
        """Alert callback should be called on fallback."""
        alerts = []
        monitor.set_alert_callback(lambda event: alerts.append(event))

        monitor.check_vault_health(is_reachable=False)

        assert len(alerts) == 1
        assert alerts[0].state == FailsafeState.CLASSICAL_FALLBACK
        assert alerts[0].vault_reachable is False

    def test_disabled_failsafe(self):
        """When disabled, failsafe should always return NORMAL."""
        config = FailsafeConfig(enabled=False)
        monitor = FailsafeMonitor(config)

        state = monitor.check_latency(9999.0)
        assert state == FailsafeState.NORMAL

        state = monitor.check_vault_health(is_reachable=False)
        assert state == FailsafeState.NORMAL

    def test_stats(self, monitor):
        monitor.check_vault_health(is_reachable=False)
        stats = monitor.stats

        assert stats["state"] == "fallback"
        assert stats["is_pq_active"] is False
        assert stats["total_failsafe_events"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
