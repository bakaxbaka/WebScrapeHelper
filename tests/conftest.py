"""Shared pytest fixtures for the WebScrapeHelper test suite."""

import pytest

from webapp import create_app


@pytest.fixture()
def app():
    application = create_app()
    application.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_SECRET="test-secret",
    )
    return application


@pytest.fixture()
def client(app):
    return app.test_client()
