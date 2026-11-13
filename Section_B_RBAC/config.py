"""Application configuration. All secrets come from environment variables (see .env.example)."""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _env_bool(name, default):
    return os.environ.get(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


def _default_db_uri():
    path = os.path.join(BASE_DIR, "instance", "bank.db").replace("\\", "/")
    return f"sqlite:///{path}"


class Config:
    # Must be supplied through the environment in any real deployment. If it is missing the app
    # generates a temporary key at start-up (sessions then reset on restart) and logs a warning.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", _default_db_uri())
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Secure session cookie configuration
    SESSION_COOKIE_NAME = "bank_session"
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Strict"      # not sent on cross-site requests (CSRF mitigation)
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)  # set to 1 behind HTTPS

    # Session expiry (enforced on the server, in the database)
    SESSION_IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", "15"))
    SESSION_ABSOLUTE_HOURS = int(os.environ.get("SESSION_ABSOLUTE_HOURS", "8"))

    # CSRF protection (Flask-WTF) for every state-changing form
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    MAX_CONTENT_LENGTH = 16 * 1024          # reject oversized request bodies

    # Show demo credentials on the login page. Development only; set to 0 for anything shared.
    SHOW_DEMO_CREDENTIALS = _env_bool("SHOW_DEMO_CREDENTIALS", True)
