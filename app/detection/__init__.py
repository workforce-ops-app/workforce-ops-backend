"""Detection: notice input that looks like an attack, and record it, never block it.

See docs/features/detection.md and decision 0030. This package is plain Python with no
FastAPI or database code (rule DE10): the detection layer (DT4) feeds it request values,
and the detection study (research repository) scores the very same code.
"""

from app.detection.detector import Finding, inspect, kinds, matches
from app.detection.normalize import normalize
from app.detection.patterns import KINDS, PATTERNS, Pattern

__all__ = ["KINDS", "PATTERNS", "Finding", "Pattern", "inspect", "kinds", "matches", "normalize"]
