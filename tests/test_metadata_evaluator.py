"""
Tests for the Metadata Evaluator.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import setup_logger
from src.config import ClassifierConfig, DataCategory
from src.metadata_evaluator import MetadataEvaluator, Action, Priority


@pytest.fixture(autouse=True)
def init_logger():
    setup_logger(level="WARNING", fmt="plain")


@pytest.fixture
def config() -> ClassifierConfig:
    return ClassifierConfig(
        ncsc_deadline_year=2035,
        data_categories={
            "satellite_keys": DataCategory(
                label="Satellite Encryption Keys",
                shelf_life_years=30,
                priority="critical",
            ),
            "pension_records": DataCategory(
                label="Employee Pension Records",
                shelf_life_years=50,
                priority="critical",
            ),
            "general_comms": DataCategory(
                label="General Communications",
                shelf_life_years=5,
                priority="low",
            ),
            "council_planning": DataCategory(
                label="Council Planning Documents",
                shelf_life_years=20,
                priority="medium",
            ),
        },
        metadata_header="X-PQ-Data-Class",
        default_action="apply_shield",
    )


class TestMetadataEvaluator:
    """Test the NCSC-aligned data classification logic."""

    def test_satellite_keys_shielded(self, config):
        """Satellite keys (30yr shelf life) must be shielded."""
        evaluator = MetadataEvaluator(config)
        result = evaluator.evaluate(metadata_header="satellite_keys")

        assert result.action == Action.APPLY_SHIELD
        assert result.priority == Priority.CRITICAL
        assert result.shelf_life_years == 30
        assert result.data_expiry_year > 2035

    def test_pension_records_shielded(self, config):
        """Pension records (50yr shelf life) must be shielded."""
        evaluator = MetadataEvaluator(config)
        result = evaluator.evaluate(metadata_header="pension_records")

        assert result.action == Action.APPLY_SHIELD
        assert result.data_expiry_year > 2035

    def test_general_comms_pass_through(self, config):
        """General comms (5yr shelf life) should pass through."""
        evaluator = MetadataEvaluator(config)
        result = evaluator.evaluate(metadata_header="general_comms")

        assert result.action == Action.PASS_THROUGH
        assert result.priority == Priority.LOW
        assert result.data_expiry_year <= 2035

    def test_unknown_data_default_shield(self, config):
        """Unknown data with default_action=apply_shield should be shielded."""
        evaluator = MetadataEvaluator(config)
        result = evaluator.evaluate(metadata_header=None)

        assert result.action == Action.APPLY_SHIELD
        assert result.data_class == "unknown"

    def test_custom_shelf_life(self, config):
        """Custom shelf life should be evaluated correctly."""
        evaluator = MetadataEvaluator(config)

        # 15 years from 2026 = 2041 > 2035 → shield
        result = evaluator.evaluate(custom_shelf_life=15)
        assert result.action == Action.APPLY_SHIELD

        # 3 years from 2026 = 2029 < 2035 → pass through
        result = evaluator.evaluate(custom_shelf_life=3)
        assert result.action == Action.PASS_THROUGH

    def test_evaluate_all_categories(self, config):
        """Evaluate all configured categories at once."""
        evaluator = MetadataEvaluator(config)
        results = evaluator.evaluate_all_categories()

        assert len(results) == 4
        assert results["satellite_keys"].action == Action.APPLY_SHIELD
        assert results["general_comms"].action == Action.PASS_THROUGH

    def test_stats_tracking(self, config):
        """Test that evaluation stats are tracked."""
        evaluator = MetadataEvaluator(config)
        evaluator.evaluate(metadata_header="satellite_keys")
        evaluator.evaluate(metadata_header="general_comms")

        stats = evaluator.stats
        assert stats["total_evaluated"] == 2
        assert stats["shielded"] >= 1
        assert stats["passed_through"] >= 1

    def test_boundary_shelf_life(self, config):
        """Test data that expires exactly at the NCSC deadline."""
        evaluator = MetadataEvaluator(config)
        # If current year is 2026, shelf_life=9 → expires 2035 (not > 2035)
        result = evaluator.evaluate(custom_shelf_life=9)
        assert result.action == Action.PASS_THROUGH

        # shelf_life=10 → expires 2036 (> 2035) → shield
        result = evaluator.evaluate(custom_shelf_life=10)
        assert result.action == Action.APPLY_SHIELD


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
