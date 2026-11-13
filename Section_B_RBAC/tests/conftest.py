"""Shared pytest fixtures. Each test gets its own fresh SQLite database in a temporary folder."""
import pytest

from app import create_app
from extensions import db

TEST_SECRET = "pytest-only-secret-key-not-used-anywhere-else-0123456789"
DEMO = {
    "customer": "Customer#2026",
    "customer2": "Customer2#2026",
    "manager": "Manager#2026",
    "admin": "Admin#2026",
}


@pytest.fixture()
def make_app(tmp_path):
    """Factory so individual tests can change configuration (for example, enable CSRF)."""
    created = []

    def factory(**overrides):
        config = {
            "TESTING": True,
            "SECRET_KEY": TEST_SECRET,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
            "WTF_CSRF_ENABLED": False,        # enabled explicitly in the CSRF tests
            "SHOW_DEMO_CREDENTIALS": False,
        }
        config.update(overrides)
        application = create_app(config)
        created.append(application)
        return application

    yield factory
    for application in created:
        with application.app_context():
            db.session.remove()
            db.drop_all()


@pytest.fixture()
def app(make_app):
    return make_app()


@pytest.fixture()
def client(app):
    return app.test_client()


def login_as(app, username):
    """Return a test client logged in as the given demo user."""
    client = app.test_client()
    response = client.post("/login", data={"username": username, "password": DEMO[username]})
    assert response.status_code == 302, f"login as {username} failed: {response.status_code}"
    return client


@pytest.fixture()
def customer(app):
    return login_as(app, "customer")


@pytest.fixture()
def customer2(app):
    return login_as(app, "customer2")


@pytest.fixture()
def manager(app):
    return login_as(app, "manager")


@pytest.fixture()
def admin(app):
    return login_as(app, "admin")


def user_id(app, username):
    from models import User
    with app.app_context():
        return db.session.scalar(db.select(User.id).filter_by(username=username))
