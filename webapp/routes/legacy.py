"""Backward-compatible route aliases for older frontend clients."""

from flask import Blueprint

from webapp.routes.api import analyze_transaction

legacy_bp = Blueprint("legacy_api", __name__)
legacy_bp.add_url_rule(
    "/analyze_transaction",
    view_func=analyze_transaction,
    methods=["POST"],
)
