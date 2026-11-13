"""Automated security tests for the Section B RBAC application.

Mapping to the assignment's required test cases is listed in ../Documentation/Test_Results.md.
"""
import re
from datetime import timedelta

import pytest

from conftest import DEMO, login_as, user_id
from extensions import db
from models import Role, Transaction, User, UserSession, utcnow


# --------------------------------------------------------------------------- 401: unauthenticated
@pytest.mark.parametrize("url", [
    "/dashboard", "/customer/dashboard", "/profile", "/profile/edit", "/customers/1",
    "/manager/dashboard", "/manager/customers", "/manager/transactions",
    "/admin/dashboard", "/admin/users", "/admin/users/new", "/admin/roles", "/admin/audit",
    "/this/route/does/not/exist",
])
def test_unauthenticated_requests_get_401(client, url):
    assert client.get(url).status_code == 401


def test_unauthenticated_state_change_gets_401(client):
    assert client.post("/admin/users/2/role", data={"role": "admin"}).status_code == 401
    assert client.post("/manager/transactions", data={}).status_code == 401


def test_failed_login_returns_401_with_generic_message(client):
    response = client.post("/login", data={"username": "customer", "password": "wrong-password"})
    assert response.status_code == 401
    assert b"Invalid username or password." in response.data


def test_unknown_user_and_wrong_password_give_same_response(client):
    a = client.post("/login", data={"username": "nobody-here", "password": "whatever-123"})
    b = client.post("/login", data={"username": "customer", "password": "whatever-123"})
    assert a.status_code == b.status_code == 401
    assert a.data.count(b"Invalid username or password.") == b.data.count(b"Invalid username or password.") == 1


# --------------------------------------------------------------------------- customer
def test_customer_views_own_profile_200(customer):
    response = customer.get("/profile")
    assert response.status_code == 200
    assert b"Alice Customer" in response.data


def test_customer_views_own_dashboard_200(customer):
    assert customer.get("/customer/dashboard").status_code == 200


def test_customer_cannot_view_another_customer_404(customer):
    assert customer.get("/customers/2").status_code == 404


def test_customer_404_is_identical_for_existing_and_missing_records(customer):
    customer.get("/customer/dashboard")       # consume the 'welcome back' flash from login
    existing = customer.get("/customers/2")
    missing = customer.get("/customers/9999")
    assert existing.status_code == missing.status_code == 404
    # CSRF tokens are random per render, so normalise them before comparing the bodies.
    strip = lambda body: re.sub(rb'name="csrf_token" value="[^"]+"', b"", body)
    assert strip(existing.data) == strip(missing.data)   # no information leak about which IDs exist


def test_customer_cannot_access_admin_pages_403(customer):
    for url in ["/admin/dashboard", "/admin/users", "/admin/users/new", "/admin/roles", "/admin/audit"]:
        assert customer.get(url).status_code == 403, url


def test_customer_cannot_access_manager_pages_403(customer):
    for url in ["/manager/dashboard", "/manager/customers", "/manager/transactions"]:
        assert customer.get(url).status_code == 403, url


def test_customer_cannot_create_or_review_transactions_403(customer):
    assert customer.post("/manager/transactions",
                         data={"customer_id": 1, "amount": "5", "description": "x"}).status_code == 403
    assert customer.post("/manager/transactions/1/status", data={"status": "approved"}).status_code == 403


def test_customer_updates_only_own_profile_fields(customer, app):
    response = customer.post("/profile/edit", data={
        "full_name": "Alice Updated", "email": "alice.new@example.test", "phone": "+1 555 9999",
        "role": "admin", "is_active": "0", "username": "root"})
    assert response.status_code == 302
    with app.app_context():
        alice = db.session.get(User, user_id(app, "customer"))
        assert alice.full_name == "Alice Updated"
        assert alice.email == "alice.new@example.test"
        assert alice.role_name == "customer"          # privilege escalation via form fields blocked
        assert alice.username == "customer"


def test_customer_cannot_edit_another_customers_profile(customer, app):
    """Profile edit always targets the logged-in user; there is no ID parameter to tamper with."""
    customer.post("/profile/edit", data={"full_name": "Hacked Name", "email": "x@example.test", "phone": ""})
    with app.app_context():
        bob = db.session.get(User, user_id(app, "customer2"))
        assert bob.full_name == "Bob Customer"


def test_profile_input_validation_rejects_script_injection(customer, app):
    response = customer.post("/profile/edit", data={
        "full_name": "<script>alert(1)</script>", "email": "alice@example.test", "phone": ""})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(User, user_id(app, "customer")).full_name == "Alice Customer"


# --------------------------------------------------------------------------- manager
def test_manager_views_customer_records_200(manager):
    assert manager.get("/manager/customers").status_code == 200
    assert manager.get("/customers/1").status_code == 200
    assert manager.get("/customers/2").status_code == 200


def test_manager_views_and_manages_transactions_200(manager):
    assert manager.get("/manager/transactions").status_code == 200
    response = manager.post("/manager/transactions/2/status", data={"status": "approved"})
    assert response.status_code == 302


def test_manager_creates_transaction(manager, app):
    response = manager.post("/manager/transactions", data={
        "customer_id": "1", "amount": "42.50", "description": "Refund"})
    assert response.status_code == 302
    page = manager.get("/manager/transactions")
    assert b"Refund" in page.data


def test_manager_cannot_manage_users_403(manager):
    assert manager.get("/admin/users").status_code == 403
    assert manager.get("/admin/users/new").status_code == 403
    assert manager.get("/admin/audit").status_code == 403


def test_manager_cannot_edit_customer_profiles_403(manager):
    assert manager.get("/profile").status_code == 403       # manager has no 'own profile' permission
    assert manager.post("/profile/edit", data={"full_name": "X Y", "email": "a@b.test"}).status_code == 403


# --------------------------------------------------------------------------- administrator
def test_admin_manages_users_200(admin):
    assert admin.get("/admin/dashboard").status_code == 200
    assert admin.get("/admin/users").status_code == 200
    assert admin.get("/admin/users/new").status_code == 200
    assert admin.get("/admin/roles").status_code == 200
    assert admin.get("/admin/audit").status_code == 200


def test_admin_creates_user(admin, app):
    response = admin.post("/admin/users/new", data={
        "username": "newteller", "full_name": "Nora Teller", "email": "nora@example.test",
        "phone": "", "role": "manager", "password": "Teller#2026x"})
    assert response.status_code == 302
    with app.app_context():
        created = db.session.scalar(db.select(User).filter_by(username="newteller"))
        assert created is not None and created.role_name == "manager"
        assert created.password_hash != "Teller#2026x"     # stored hashed


def test_admin_rejects_weak_password_when_creating_user(admin):
    response = admin.post("/admin/users/new", data={
        "username": "weakuser", "full_name": "Weak User", "email": "w@example.test",
        "phone": "", "role": "customer", "password": "short"})
    assert response.status_code == 400


def test_admin_assigns_role(admin, app):
    response = admin.post(f"/admin/users/{user_id(app, 'customer2')}/role", data={"role": "manager"})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(User, user_id(app, "customer2")).role_name == "manager"


def test_admin_cannot_change_own_role(admin, app):
    admin.post(f"/admin/users/{user_id(app, 'admin')}/role", data={"role": "customer"})
    with app.app_context():
        assert db.session.get(User, user_id(app, "admin")).role_name == "admin"


def test_admin_cannot_deactivate_self(admin, app):
    admin.post(f"/admin/users/{user_id(app, 'admin')}/status")
    with app.app_context():
        assert db.session.get(User, user_id(app, "admin")).is_active is True


def test_admin_deactivation_revokes_sessions(admin, app):
    bob = login_as(app, "customer2")
    assert bob.get("/profile").status_code == 200
    admin.post(f"/admin/users/{user_id(app, 'customer2')}/status")
    assert bob.get("/profile").status_code == 401


def test_admin_cannot_remove_core_admin_permissions(admin, app):
    with app.app_context():
        admin_role_id = db.session.scalar(db.select(Role.id).filter_by(name="admin"))
    admin.post(f"/admin/roles/{admin_role_id}", data={"permissions": ["users:manage"]})
    with app.app_context():
        role = db.session.get(Role, admin_role_id)
        assert role.has("roles:assign") and role.has("permissions:manage")


def test_admin_has_no_transaction_access_least_privilege(admin):
    assert admin.get("/manager/transactions").status_code == 403
    assert admin.get("/manager/customers").status_code == 403


# --------------------------------------------------------------------------- privilege escalation
def test_unauthorized_role_modification_rejected_for_customer(customer, app):
    response = customer.post(f"/admin/users/{user_id(app, 'customer2')}/role", data={"role": "admin"})
    assert response.status_code == 403
    with app.app_context():
        assert db.session.get(User, user_id(app, "customer2")).role_name == "customer"


def test_unauthorized_role_modification_rejected_for_manager(manager, app):
    response = manager.post(f"/admin/users/{user_id(app, 'customer')}/role", data={"role": "admin"})
    assert response.status_code == 403
    with app.app_context():
        assert db.session.get(User, user_id(app, "customer")).role_name == "customer"


def test_manager_cannot_change_permissions_403(manager, app):
    with app.app_context():
        role_id = db.session.scalar(db.select(Role.id).filter_by(name="manager"))
    response = manager.post(f"/admin/roles/{role_id}", data={"permissions": ["users:manage"]})
    assert response.status_code == 403


def test_role_cannot_be_set_to_unknown_value(admin, app):
    response = admin.post(f"/admin/users/{user_id(app, 'customer')}/role", data={"role": "superuser"})
    assert response.status_code == 400


def test_forged_role_header_is_ignored(customer):
    assert customer.get("/admin/users", headers={"X-Role": "admin", "X-User-Role": "admin"}).status_code == 403


def test_forged_session_cookie_is_rejected(client):
    client.set_cookie("bank_session", "forged.value.that.is.not.signed")
    assert client.get("/profile").status_code == 401


def test_removing_customer_permission_takes_effect_immediately(admin, customer, app):
    """Permissions are read from the database on each request, so changes apply at once."""
    with app.app_context():
        role_id = db.session.scalar(db.select(Role.id).filter_by(name="customer"))
    admin.post(f"/admin/roles/{role_id}", data={"permissions": ["profile:update_own"]})
    assert customer.get("/profile").status_code == 403
    assert customer.get("/customer/dashboard").status_code == 403


# --------------------------------------------------------------------------- session management
def test_invalid_session_id_returns_401(client, customer):
    client.set_cookie("bank_session", "x")
    assert client.get("/profile").status_code == 401


def test_idle_session_expires_returns_401(customer, app):
    with app.app_context():
        record = db.session.scalar(db.select(UserSession).order_by(UserSession.created_at.desc()))
        record.last_seen = utcnow() - timedelta(minutes=app.config["SESSION_IDLE_MINUTES"] + 1)
        db.session.commit()
    assert customer.get("/profile").status_code == 401


def test_absolute_session_lifetime_expires_returns_401(customer, app):
    with app.app_context():
        record = db.session.scalar(db.select(UserSession).order_by(UserSession.created_at.desc()))
        record.created_at = utcnow() - timedelta(hours=app.config["SESSION_ABSOLUTE_HOURS"] + 1)
        record.last_seen = utcnow()
        db.session.commit()
    assert customer.get("/profile").status_code == 401


def test_logout_revokes_server_session_even_if_cookie_is_replayed(app):
    client = login_as(app, "customer")
    saved = client.get_cookie("bank_session").value
    assert client.post("/logout").status_code == 302
    client.set_cookie("bank_session", saved)           # attacker replays the old cookie
    assert client.get("/profile").status_code == 401


def test_session_cookie_has_secure_attributes(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "customer", "password": DEMO["customer"]})
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


def test_security_headers_present(client):
    response = client.get("/login")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_authenticated_pages_are_not_cached(customer):
    assert "no-store" in customer.get("/profile").headers["Cache-Control"]


# --------------------------------------------------------------------------- CSRF
@pytest.fixture()
def csrf_app(make_app):
    return make_app(WTF_CSRF_ENABLED=True)


def _token_from(html):
    match = re.search(rb'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token in form"
    return match.group(1).decode()


def test_login_form_requires_csrf_token(csrf_app):
    client = csrf_app.test_client()
    response = client.post("/login", data={"username": "customer", "password": DEMO["customer"]})
    assert response.status_code == 400


def test_login_with_valid_csrf_token_succeeds(csrf_app):
    client = csrf_app.test_client()
    page = client.get("/login")
    token = _token_from(page.data)
    response = client.post("/login", data={"username": "customer", "password": DEMO["customer"],
                                           "csrf_token": token})
    assert response.status_code == 302


def test_state_changing_form_requires_csrf_token(csrf_app):
    client = csrf_app.test_client()
    token = _token_from(client.get("/login").data)
    client.post("/login", data={"username": "admin", "password": DEMO["admin"], "csrf_token": token})
    # Role change without a token is rejected even though the user is an authenticated admin.
    response = client.post(f"/admin/users/{user_id(csrf_app, 'customer')}/role", data={"role": "manager"})
    assert response.status_code == 400
    with csrf_app.app_context():
        assert db.session.get(User, user_id(csrf_app, "customer")).role_name == "customer"


# --------------------------------------------------------------------------- input validation
def test_login_rejects_oversized_password_without_hashing(client):
    response = client.post("/login", data={"username": "customer", "password": "x" * 500})
    assert response.status_code == 401


def test_amount_validation_rejects_negative_amount(manager, app):
    response = manager.post("/manager/transactions", follow_redirects=True, data={
        "customer_id": "1", "amount": "-5", "description": "bad"})
    assert b"Amount must be between" in response.data
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(Transaction.id)).where(
            Transaction.description == "bad")) == 0


def test_amount_validation_rejects_nan(manager):
    response = manager.post("/manager/transactions", follow_redirects=True, data={
        "customer_id": "1", "amount": "NaN", "description": "bad"})
    assert b"Enter a valid amount." in response.data
