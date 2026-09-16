from __future__ import annotations

RANK = {"Low": 0.25, "Medium": 0.50, "High": 0.75, "Critical": 1.00}


def to_score(severity: str | None, confidence: float) -> int:
    if not severity or confidence <= 0:
        return 0
    rank = RANK.get(severity)
    if rank is None:
        return 0
    value = int(round(100.0 * rank * float(confidence)))
    return max(0, min(100, value))
