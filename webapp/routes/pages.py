"""HTML page routes."""

from flask import Blueprint, render_template, send_from_directory

pages_bp = Blueprint("pages", __name__)


@pages_bp.get("/")
def index():
    return render_template("index.html")


@pages_bp.get("/transaction")
def transaction_page():
    return render_template("transaction.html")


@pages_bp.get("/address")
def address_page():
    return render_template("address.html")


@pages_bp.get("/ecdsa-analysis")
def ecdsa_analysis_page():
    return render_template("ecdsa_analysis.html")


@pages_bp.get("/standalone-calculator")
def standalone_calculator_page():
    return render_template("standalone_calculator.html")


@pages_bp.get("/download-calculator")
def download_calculator():
    return send_from_directory(
        "../static",
        "ecdsa_standalone.html",
        mimetype="text/html",
        as_attachment=True,
        download_name="bitcoin_ecdsa_calculator.html",
    )
