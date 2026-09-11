"""Centralized application configuration."""

import os


class Config:
    SECRET_KEY = os.environ.get("SESSION_SECRET", "dev-only-change-me")
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024)))
    ANALYSIS_MAX_TXS = int(os.environ.get("ANALYSIS_MAX_TXS", "500"))
    HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "10"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    PORT = int(os.environ.get("PORT", "5000"))
