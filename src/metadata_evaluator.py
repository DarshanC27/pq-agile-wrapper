"""
Metadata Evaluator — NCSC-Aligned Data Classification
=====================================================

Implements the "Agile Mosca" decision logic:
  IF data_expiry > NCSC_2035_DEADLINE THEN action = "apply_shield"
  ELSE action = "pass_through"

Examines packet metadata headers to determine data classification
and whether the Shadow Wrap should be applied.
"""

import time
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict

from .config import ClassifierConfig, DataCategory
from .logger import get_logger


class Action(Enum):
    """Decision output from the evaluator."""
    APPLY_SHIELD = "apply_shield"
    PASS_THROUGH = "pass_through"


class Priority(Enum):
    """Data priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ClassificationResult:
    """Result of evaluating a data packet."""
    action: Action
    data_class: str
    category_label: str
    priority: Priority
    shelf_life_years: int
    data_expiry_year: int
    reason: str
    evaluated_at: float


class MetadataEvaluator:
    """
    Evaluates incoming data packets against NCSC 2035 migration criteria.

    The evaluator reads a metadata header from each packet to determine
    its data classification. Based on the shelf-life of that data category,
    it decides whether to apply the quantum-resistant Shadow Wrap.
    """

    def __init__(self, config: ClassifierConfig):
        self.config = config
        self.log = get_logger()
        self.current_year = datetime.now().year
        self._stats = {
            "total_evaluated": 0,
            "shielded": 0,
            "passed_through": 0,
        }

    def evaluate(
        self,
        metadata_header: Optional[str] = None,
        custom_shelf_life: Optional[int] = None,
    ) -> ClassificationResult:
        """
        Evaluate a data stream and decide: shield or pass through?

        Args:
            metadata_header: Value of the X-PQ-Data-Class header
                             (e.g. "satellite_keys", "pension_records")
            custom_shelf_life: Override shelf life in years (for ad-hoc data)

        Returns:
            ClassificationResult with the action decision
        """
        self._stats["total_evaluated"] += 1

        # Look up the data category
        if metadata_header and metadata_header in self.config.data_categories:
            cat = self.config.data_categories[metadata_header]
            data_class = metadata_header
            label = cat.label
            priority = Priority(cat.priority)
            shelf_life = cat.shelf_life_years
        elif custom_shelf_life is not None:
            data_class = "custom"
            label = "Custom Data"
            priority = Priority.MEDIUM
            shelf_life = custom_shelf_life
        else:
            # Unknown data — use default action
            data_class = "unknown"
            label = "Unclassified Data"
            priority = Priority.MEDIUM
            shelf_life = 15  # Conservative default

        # Calculate when this data "expires" (no longer needs confidentiality)
        data_expiry_year = self.current_year + shelf_life

        # THE CORE DECISION: Does this data outlive the NCSC 2035 deadline?
        if data_expiry_year > self.config.ncsc_deadline_year:
            action = Action.APPLY_SHIELD
            reason = (
                f"Data expires in {data_expiry_year}, which is AFTER the "
                f"NCSC {self.config.ncsc_deadline_year} quantum deadline. "
                f"Applying ML-KEM Shadow Wrap to protect against HNDL attacks."
            )
            self._stats["shielded"] += 1
        else:
            action = Action.PASS_THROUGH
            reason = (
                f"Data expires in {data_expiry_year}, which is BEFORE the "
                f"NCSC {self.config.ncsc_deadline_year} deadline. "
                f"Classical encryption is sufficient."
            )
            self._stats["passed_through"] += 1

        # Override: if default_action is "apply_shield" and data is unknown,
        # shield it anyway (conservative / zero-trust approach)
        if (
            data_class == "unknown"
            and self.config.default_action == "apply_shield"
        ):
            action = Action.APPLY_SHIELD
            reason = (
                "Unclassified data with default-shield policy. "
                "Applying ML-KEM Shadow Wrap as a precaution."
            )
            self._stats["shielded"] += 1
            self._stats["passed_through"] -= 1

        result = ClassificationResult(
            action=action,
            data_class=data_class,
            category_label=label,
            priority=priority,
            shelf_life_years=shelf_life,
            data_expiry_year=data_expiry_year,
            reason=reason,
            evaluated_at=time.time(),
        )

        log_msg = (
            f"[EVALUATE] {label} ({data_class}) → {action.value} | "
            f"Shelf-life: {shelf_life}y | Expiry: {data_expiry_year} | "
            f"Priority: {priority.value}"
        )
        if action == Action.APPLY_SHIELD:
            self.log.info(log_msg)
        else:
            self.log.debug(log_msg)

        return result

    def evaluate_all_categories(self) -> Dict[str, ClassificationResult]:
        """Evaluate all configured data categories. Useful for audits."""
        results = {}
        for key in self.config.data_categories:
            results[key] = self.evaluate(metadata_header=key)
        return results

    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "ncsc_deadline": self.config.ncsc_deadline_year,
            "configured_categories": len(self.config.data_categories),
        }
