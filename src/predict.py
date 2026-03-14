"""
ML engine + prediction service for the phishing detection platform.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np

from .config import MODEL_PATH, MODEL_VERSION
from .features import (
    AttachmentFinding,
    Indicator,
    LinkFinding,
    analyze_email_content,
    analyze_email_headers,
    extract_and_assess_attachments,
    extract_and_assess_links,
)
from .risk import compute_risk_score, risk_level_from_score

LOGGER = logging.getLogger(__name__)

_PIPELINE_PACKAGE: Optional[object] = None


class ModelNotLoadedError(RuntimeError):
    pass


@dataclass
class PredictionOutput:
    label: int
    label_name: str
    phishing_probability: float
    confidence: float
    risk_score: int
    risk_level: str
    model_version: str
    indicators: Dict[str, List[Indicator]]
    link_findings: List[LinkFinding]
    attachment_findings: List[AttachmentFinding]
    explanation: str


# =========================
# MODEL LOADING
# =========================

def load_model(path: str = MODEL_PATH):
    global _PIPELINE_PACKAGE

    if _PIPELINE_PACKAGE is not None:
        return _PIPELINE_PACKAGE

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found at {path!r}. Train the model first."
        )

    LOGGER.info("Loading model from %s", path)
    _PIPELINE_PACKAGE = joblib.load(path)
    return _PIPELINE_PACKAGE


def _get_best_pipeline():
    pkg = load_model()

    # Case 1 → packaged dict model
    if isinstance(pkg, dict):
        pipe = pkg.get("best_pipeline")
        if pipe is None:
            raise ModelNotLoadedError("Best pipeline missing inside model package.")
        return pipe

    # Case 2 → direct pipeline model
    return pkg


def _get_online_clf_and_vectorizer():
    pkg = load_model()

    if isinstance(pkg, dict):
        pipe = pkg.get("best_pipeline")
        online = pkg.get("online_clf")
        classes = pkg.get("classes")

        if pipe is None or online is None or classes is None:
            raise ModelNotLoadedError("Online learning components missing.")

        vectorizer = pipe.named_steps["tfidf"]
        return online, vectorizer, classes

    raise ModelNotLoadedError("Online training not supported for this model type.")


def get_model_version() -> str:
    try:
        pkg = load_model()
        if isinstance(pkg, dict):
            return str(pkg.get("version", MODEL_VERSION))
        return MODEL_VERSION
    except Exception:
        return MODEL_VERSION


# =========================
# PREDICTION ENGINE
# =========================

def predict_email(text: str) -> PredictionOutput:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Email text must be a non-empty string.")

    pipe = _get_best_pipeline()

    # Probability prediction
    proba = pipe.predict_proba([text])[0]
    classes = list(pipe.classes_)

    try:
        phishing_index = classes.index(1)
    except ValueError:
        raise RuntimeError(
            f"Model classes do not contain label '1'. Found: {classes}"
        )

    phishing_prob = float(proba[phishing_index])
    label = 1 if phishing_prob >= 0.5 else 0
    label_name = "phishing" if label == 1 else "legitimate"
    confidence = phishing_prob * 100 if label == 1 else (1 - phishing_prob) * 100

    # Feature analysis
    text_indicators = analyze_email_content(text)
    header_indicators = analyze_email_headers(text)
    
    # Merge dictionaries
    indicators = text_indicators.copy()
    for cat, inds in header_indicators.items():
        indicators.setdefault(cat, []).extend(inds)
        
    link_findings = extract_and_assess_links(text)
    attachment_findings = extract_and_assess_attachments(text)

    # Risk scoring
    risk_score = compute_risk_score(phishing_prob, indicators)
    risk_score = _apply_link_attachment_risk(
        risk_score, link_findings, attachment_findings
    )
    risk_level = risk_level_from_score(risk_score)
    version = get_model_version()

    # Explanation
    explanation_parts: List[str] = []
    explanation_parts.append(
        f"Model classifies this email as {label_name.upper()} with {confidence:.1f}% confidence."
    )
    explanation_parts.append(
        f"Overall risk score is {risk_score}/100 ({risk_level} risk)."
    )

    if indicators:
        explanation_parts.append(
            "Detected indicators include: "
            + ", ".join(sorted(set(t for t in indicators.keys())))
            + "."
        )
    else:
        explanation_parts.append("No strong phishing indicators detected.")

    explanation = " ".join(explanation_parts)

    return PredictionOutput(
        label=label,
        label_name=label_name,
        phishing_probability=phishing_prob,
        confidence=confidence,
        risk_score=risk_score,
        risk_level=risk_level,
        model_version=version,
        indicators=indicators,
        link_findings=link_findings,
        attachment_findings=attachment_findings,
        explanation=explanation,
    )


def predict_email_rich(text: str) -> Dict[str, object]:
    out = predict_email(text)
    return {
        "label": out.label,
        "label_name": out.label_name,
        "phishing_probability": out.phishing_probability,
        "confidence": out.confidence,
        "risk_score": out.risk_score,
        "risk_level": out.risk_level,
        "model_version": out.model_version,
        "indicators": {
            key: [
                {"type": ind.type, "value": ind.value, "severity": ind.severity}
                for ind in inds
            ]
            for key, inds in out.indicators.items()
        },
        "links": [
            {
                "url": f.url,
                "domain": f.domain,
                "verdict": f.verdict,
                "risk_score": f.risk_score,
                "reasons": f.reasons,
            }
            for f in out.link_findings
        ],
        "attachments": [
            {
                "filename": f.filename,
                "verdict": f.verdict,
                "risk_score": f.risk_score,
                "reasons": f.reasons,
            }
            for f in out.attachment_findings
        ],
        "explanation": out.explanation,
    }


# =========================
# RISK ADJUSTMENT
# =========================

def _apply_link_attachment_risk(base_score, links, attachments):
    bonus = 0

    for l in links:
        if l.verdict == "PHISHING":
            bonus += 10
        elif l.verdict == "SUSPICIOUS":
            bonus += 5

    for a in attachments:
        if a.verdict == "PHISHING":
            bonus += 12
        elif a.verdict == "SUSPICIOUS":
            bonus += 6

    bonus = min(25, bonus)
    return int(min(100, max(0, base_score + bonus)))


# =========================
# ONLINE LEARNING
# =========================

def incremental_update(text: str, label: int) -> bool:
    online, vectorizer, classes = _get_online_clf_and_vectorizer()

    X = vectorizer.transform([text])
    y = np.array([label])

    online.partial_fit(X, y, classes=classes)

    pkg = load_model()
    if isinstance(pkg, dict):
        pkg["online_clf"] = online
        joblib.dump(pkg, MODEL_PATH)

    return True


class PredictionService:
    def analyze_email(self, text: str) -> Dict[str, object]:
        return predict_email_rich(text)

    def incremental_update(self, text: str, label: int) -> bool:
        return incremental_update(text, label)

    # convenience wrappers used by the web application
    def load_model_if_needed(self):
        """Attempt to load the model; errors propagate to caller."""
        load_model()

    def reload_model(self):
        """Force a reload of the model file from disk.

        This clears the cached package and then reloads. Useful for admin
        interface when a new model is deployed.
        """
        global _PIPELINE_PACKAGE
        _PIPELINE_PACKAGE = None
        load_model()
