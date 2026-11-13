"""Input validation: allow-lists, length limits and no control characters.

Output is additionally escaped by Jinja2 autoescaping when rendered, so stored values cannot
inject HTML or script into the pages.
"""
import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,99}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
PHONE_RE = re.compile(r"^\+?[0-9 ()-]{7,20}$")
DESCRIPTION_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,200}$")

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128               # also limits the work an attacker can force on the hasher
MIN_AMOUNT = Decimal("0.01")
MAX_AMOUNT = Decimal("100000.00")


def _text(form, key):
    return (form.get(key) or "").strip()


def validate_login(username, password):
    """Generic message on purpose: do not reveal which field was wrong."""
    if not username or len(username) > 32 or not password or len(password) > MAX_PASSWORD_LENGTH:
        return ["Invalid username or password."]
    return []


def validate_profile(form):
    data = {key: _text(form, key) for key in ("full_name", "email", "phone")}
    errors = []
    if not NAME_RE.match(data["full_name"]):
        errors.append("Full name: 2-100 letters, spaces, apostrophes or hyphens.")
    if len(data["email"]) > 120 or not EMAIL_RE.match(data["email"]):
        errors.append("Enter a valid email address.")
    if data["phone"] and not PHONE_RE.match(data["phone"]):
        errors.append("Phone: digits, spaces, +, ( ) and - only (7-20 characters).")
    return data, errors


def validate_password(password):
    errors = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    if not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
        errors.append("Password must contain at least one letter and one number.")
    return errors


def validate_new_user(form):
    data = {key: _text(form, key) for key in ("username", "full_name", "email", "phone", "role")}
    password = form.get("password") or ""
    errors = []
    if not USERNAME_RE.match(data["username"]):
        errors.append("Username: 3-32 letters, digits, dot, underscore or hyphen.")
    if not NAME_RE.match(data["full_name"]):
        errors.append("Full name: 2-100 letters, spaces, apostrophes or hyphens.")
    if len(data["email"]) > 120 or not EMAIL_RE.match(data["email"]):
        errors.append("Enter a valid email address.")
    if data["phone"] and not PHONE_RE.match(data["phone"]):
        errors.append("Phone: digits, spaces, +, ( ) and - only (7-20 characters).")
    errors.extend(validate_password(password))
    data["password"] = password
    return data, errors


def validate_transaction(form):
    errors = []
    customer_id = None
    try:
        customer_id = int(_text(form, "customer_id"))
    except ValueError:
        errors.append("Choose a customer.")

    amount_cents = None
    try:
        amount = Decimal(_text(form, "amount"))
        if not amount.is_finite():
            raise InvalidOperation
        amount = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if not (MIN_AMOUNT <= amount <= MAX_AMOUNT):
            errors.append("Amount must be between 0.01 and 100,000.00.")
        else:
            amount_cents = int(amount * 100)
    except (InvalidOperation, ValueError):
        errors.append("Enter a valid amount.")

    description = _text(form, "description")
    if not DESCRIPTION_RE.match(description):
        errors.append("Description: 1-200 characters, no angle brackets or control characters.")

    return {"customer_id": customer_id, "amount_cents": amount_cents,
            "description": description}, errors
