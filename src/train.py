"""
Training script for the phishing email detection model.

Models evaluated:
- Logistic Regression
- Linear SVM (with probability calibration)
- Random Forest
- SGDClassifier (supports partial_fit for online learning)

The best model by F1 score is selected as the primary engine.
An SGDClassifier is also trained for incremental updates and packaged together.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from .config import (
    MODEL_PATH,
    MODEL_VERSION,
    RANDOM_STATE,
    TEST_SIZE,
    MAX_FEATURES,
    NGRAM_RANGE,
    MIN_DF,
    MAX_DF,
)
from .preprocess import prepare_dataset

LOGGER = logging.getLogger(__name__)


def _build_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        ngram_range=NGRAM_RANGE,
        min_df=MIN_DF,
        max_df=MAX_DF,
        max_features=MAX_FEATURES,
        sublinear_tf=True,
        stop_words="english",
    )


def _build_models() -> Dict[str, object]:
    return {
        "logreg": LogisticRegression(
            max_iter=300,
            class_weight="balanced",
            n_jobs=-1,
            solver="lbfgs",
        ),
        "lin_svm": CalibratedClassifierCV(
            base_estimator=LinearSVC(
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
            cv=3,
        ),
        "rf": RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            n_jobs=-1,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
        ),
        "sgd": SGDClassifier(
            loss="log_loss",
            max_iter=1000,
            alpha=1e-4,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),
    }


def _evaluate_pipeline(
    name: str, pipeline: Pipeline, X_test, y_test
) -> Dict[str, object]:
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1)
    rec = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    cm = confusion_matrix(y_test, y_pred)

    LOGGER.info("[%s] Accuracy:  %.4f", name, acc)
    LOGGER.info("[%s] Precision: %.4f", name, prec)
    LOGGER.info("[%s] Recall:    %.4f", name, rec)
    LOGGER.info("[%s] F1-score:  %.4f", name, f1)
    LOGGER.info("[%s] Confusion matrix:\n%s", name, cm)
    LOGGER.info("[%s] Classification report:\n%s", name, classification_report(y_test, y_pred))

    return {
        "name": name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "cm": cm,
    }


def train_and_select_best() -> Tuple[Pipeline, SGDClassifier, np.ndarray]:
    LOGGER.info("Preparing dataset...")
    X, y = prepare_dataset()

    LOGGER.info("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    vectorizer = _build_vectorizer()
    models = _build_models()

    results = {}
    best_name = None
    best_f1 = -1.0
    best_pipeline: Pipeline | None = None

    LOGGER.info("Training candidate models...")
    for name, clf in models.items():
        pipe = Pipeline(
            steps=[
                ("tfidf", vectorizer),
                ("clf", clf),
            ]
        )
        LOGGER.info("Fitting model: %s", name)
        pipe.fit(X_train, y_train)

        metrics = _evaluate_pipeline(name, pipe, X_test, y_test)
        results[name] = metrics

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_name = name
            best_pipeline = pipe

    assert best_pipeline is not None
    LOGGER.info("Best model by F1: %s (F1=%.4f)", best_name, best_f1)

    # Train a fresh SGDClassifier for online learning (partial_fit) on full training set
    LOGGER.info("Training online SGD classifier for incremental learning...")
    online_clf = SGDClassifier(
        loss="log_loss",
        max_iter=5,
        alpha=1e-4,
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    classes = np.array([0, 1])
    online_clf.partial_fit(X_train_vec, y_train, classes=classes)

    setattr(best_pipeline, "model_version", MODEL_VERSION)
    return best_pipeline, online_clf, classes


def save_model(
    best_pipeline: Pipeline,
    online_clf: SGDClassifier,
    classes: np.ndarray,
    path: str = MODEL_PATH,
) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)

    payload = {
        "best_pipeline": best_pipeline,
        "online_clf": online_clf,
        "classes": classes,
        "version": getattr(best_pipeline, "model_version", MODEL_VERSION),
    }

    joblib.dump(payload, path)
    LOGGER.info("Model package saved to %s", path)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    LOGGER.info("Starting training run. version=%s", MODEL_VERSION)
    best_pipeline, online_clf, classes = train_and_select_best()
    save_model(best_pipeline, online_clf, classes, MODEL_PATH)
    LOGGER.info("Training run complete.")


if __name__ == "__main__":
    main()