"""
Dataset loading and text preprocessing for the phishing email detector.

No model fitting happens here to avoid data leakage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple

import pandas as pd

from .config import DATA_PATH

LOGGER = logging.getLogger(__name__)


@dataclass
class DatasetConfig:
    path: str = DATA_PATH
    text_column: str = "Email Text"
    label_column: str = "Email Type"
    safe_label_value: str = "Safe Email"
    phishing_label_value: str = "Phishing Email"


URL_PATTERN = re.compile(r"https?://\S+|www\.\S+")
HTML_TAG_PATTERN = re.compile(r"<.*?>")
NON_ALPHA_PATTERN = re.compile(r"[^a-zA-Z\s]+")
WHITESPACE_PATTERN = re.compile(r"\s+")


def clean_text(text: str) -> str:
    if not isinstance(text, str):
        text = "" if text is None else str(text)

    text = text.strip().lower()
    text = URL_PATTERN.sub(" url ", text)
    text = HTML_TAG_PATTERN.sub(" ", text)
    text = NON_ALPHA_PATTERN.sub(" ", text)
    text = WHITESPACE_PATTERN.sub(" ", text).strip()
    return text


def preprocess_corpus(texts: Iterable[str]) -> List[str]:
    return [clean_text(t) for t in texts]


def load_raw_dataset(config: DatasetConfig | None = None) -> pd.DataFrame:
    config = config or DatasetConfig()

    LOGGER.info("Loading dataset from %s", config.path)
    df = pd.read_csv(config.path)
    LOGGER.info("Raw rows: %d", len(df))

    df = df.drop_duplicates()

    df = df[[config.text_column, config.label_column]].rename(
        columns={config.text_column: "text", config.label_column: "label"}
    )

    label_map = {
        config.safe_label_value: 0,
        config.phishing_label_value: 1,
    }
    df["label"] = df["label"].map(label_map)
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    LOGGER.info("Class balance after mapping:\n%s", df["label"].value_counts())
    return df


def prepare_dataset(config: DatasetConfig | None = None) -> Tuple[pd.Series, pd.Series]:
    df = load_raw_dataset(config)
    LOGGER.info("Cleaning text column...")
    df["text"] = preprocess_corpus(df["text"])
    return df["text"], df["label"]