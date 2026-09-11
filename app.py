"""Compatibility entry point for the refactored Flask application.

The actual application is organized under ``webapp``. Keeping ``app`` exported
here preserves imports such as ``from app import app`` used by WSGI servers and
existing integrations.
"""

from webapp import app, create_app

__all__ = ["app", "create_app"]
