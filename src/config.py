"""
Configuration for the phishing detection platform.
"""

from __future__ import annotations

DATA_PATH = "data/emails.csv"
MODEL_PATH = "models/phishing_detector.pkl"
MODEL_VERSION = "v1.1.0"

RANDOM_STATE = 42
TEST_SIZE = 0.2
MAX_FEATURES = 20000
NGRAM_RANGE = (1, 2)
MIN_DF = 2
MAX_DF = 0.9