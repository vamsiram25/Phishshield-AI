"""
Risk scoring engine for phishing detection.

Combines ML probability with indicator severity to produce a 0–100 score and risk band.
"""

from __future__ import annotations

from typing import Dict, List

from .features import Indicator


def compute_risk_score(
    phishing_prob: float, indicators: Dict[str, List[Indicator]]
) -> int:
    base = phishing_prob * 80.0

    bonus = 0.0
    for group in indicators.values():
        for ind in group:
            if ind.severity == "HIGH":
                bonus += 8.0
            elif ind.severity == "MEDIUM":
                bonus += 4.0
            else:
                bonus += 2.0

    score = int(min(100.0, base + min(bonus, 20.0)))
    return score


def risk_level_from_score(score: int) -> str:
    if score < 35:
        return "LOW"
    if score < 70:
        return "MEDIUM"
    return "HIGH"