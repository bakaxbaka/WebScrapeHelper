"""Application factory for WebScrapeHelper."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, request

from webapp.config import Config
from webapp.routes.api import api_bp
from webapp.routes.pages import pages_bp

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR),
        static_folder=str(BASE_DIR / "static"),
        static_url_path="/static",
    )
    app.config.from_object(config_class)
    app.secret_key = os.environ.get("SESSION_SECRET") or "dev-only-change-me"

    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    _register_http_handlers(app)
    _register_security_headers(app)

    logger.info("Flask application initialized")
    return app


def _register_http_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(error="Bad request", status=400), 400

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Endpoint not found", status=404), 404
        return "Not Found", 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Method not allowed", status=405), 405
        return "Method Not Allowed", 405

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("Unhandled Flask exception")
        if request.path.startswith("/api/"):
            return jsonify(error="Internal server error", status=500), 500
        return "Internal Server Error", 500


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=3600"
        return response


app = create_app()
