"""Repair engine: locate the byte regions of a file that look wrong, and
(later phases) extract them and return a repaired file with a report.

Phase 2 (this release): format-aware region maps. See
``docs/repair_engine_plan.md`` for the phases still to come.
"""
from repair_engine.parsers import detect, parse
from repair_engine.regions import Region, RegionMap

__all__ = ["Region", "RegionMap", "detect", "parse"]
