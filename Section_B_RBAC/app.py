"""SecureBank - Section B: secure role-based access control (RBAC) web application.

Start:  python app.py          then open http://127.0.0.1:5000
Roles:  customer, manager, admin  (see permissions.py)

Security controls
-----------------
* Deny by default: every endpoint except those in PUBLIC_ENDPOINTS needs an authenticated session
  (401 otherwise). This hook runs before CSRF checking.
* Server-side sessions: the cookie holds a random id; the record lives in the database and can be
  revoked (logout, deactivation) and expires on idle (15 min) and absolute (8 h) timeouts.
* Authorisation on every protected route via @permission_required (403 for insufficient permission).
* Object ownership via load_customer_for_actor (404 for another customer's record).
* CSRF tokens (Flask-WTF) on every state-changing form.
* Parameterised queries only (SQLAlchemy ORM), strict input validation, Jinja2 autoescaping.
* Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy, no-store on authenticated pages.
"""
import os
import secrets
from datetime import timedelta

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request, url_for)
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import validation
from auth import (audit, end_session, load_current_user, load_customer_for_actor,
                  permission_required, start_session)
from config import Config
from extensions import csrf, db
from models import AuditLog, Permission, Role, Transaction, User, UserSession, utcnow
from permissions import PERMISSIONS, PROTECTED_ADMIN_PERMISSIONS
from seed import seed_database

PUBLIC_ENDPOINTS = {"index", "login", "health", "static"}
ROLE_HOME = {"customer": "customer_dashboard", "manager": "manager_dashboard", "admin": "admin_dashboard"}
ERROR_MESSAGES = {
    400: "The request was invalid. Please go back and try again.",
    401: "You need to log in to view this page.",
    403: "Your account does not have permission to view this page.",
    404: "The page or record you asked for was not found.",
    405: "That action is not allowed here.",
    413: "The submitted data is too large.",
}
# Equalises response time for unknown usernames and wrong passwords (prevents user enumeration by timing).
DUMMY_HASH = generate_password_hash("timing-equaliser-not-a-real-password")


def create_app(overrides=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning("SECRET_KEY is not set. Using a temporary key: sessions reset on restart. "
                           "Set SECRET_KEY in your environment (see .env.example).")
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=app.config["SESSION_ABSOLUTE_HOURS"])
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    # ------------------------------------------------------------------ deny by default
    @app.before_request
    def deny_by_default():
        g.user = load_current_user()
        if request.endpoint in PUBLIC_ENDPOINTS:
            return None
        if g.user is None:
            abort(401)
        return None

    # Registered AFTER the hook above so unauthenticated requests receive 401 before any CSRF check.
    csrf.init_app(app)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        if g.get("user") is not None:
            response.headers["Cache-Control"] = "no-store, private"
        return response

    @app.context_processor
    def inject_user():
        return {"current_user": g.get("user")}

    # ------------------------------------------------------------------ errors
    def render_error(code, message):
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return render_error(400, "Your form expired or the security token was missing. "
                                 "Reload the page and try again.")

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return render_error(error.code, ERROR_MESSAGES.get(error.code, error.description))

    # ------------------------------------------------------------------ public routes
    @app.get("/")
    def index():
        if g.user is None:
            return redirect(url_for("login"))
        return redirect(url_for(ROLE_HOME[g.user.role_name]))

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if g.user is not None:
                return redirect(url_for(ROLE_HOME[g.user.role_name]))
            return render_template("login.html", username="",
                                   show_demo=app.config["SHOW_DEMO_CREDENTIALS"])

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        errors = validation.validate_login(username, password)
        user = None
        if not errors:
            user = db.session.scalar(db.select(User).filter_by(username=username))

        if user is not None:
            ok = user.check_password(password) and user.is_active
        else:
            check_password_hash(DUMMY_HASH, password)     # same work as a real check
            ok = False

        if not ok:
            audit("login_failed", username[:32])
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username,
                                   show_demo=app.config["SHOW_DEMO_CREDENTIALS"]), 401

        start_session(user)
        audit("login", user.username)
        flash(f"Welcome back, {user.full_name}.", "success")
        return redirect(url_for(ROLE_HOME[user.role_name]))

    @app.post("/logout")
    def logout():
        audit("logout", g.user.username)
        end_session()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.get("/dashboard")
    def dashboard():
        return redirect(url_for(ROLE_HOME[g.user.role_name]))

    # ------------------------------------------------------------------ customer routes
    @app.get("/customer/dashboard")
    @permission_required("profile:view_own")
    def customer_dashboard():
        transactions = db.session.scalars(
            db.select(Transaction).filter_by(customer_id=g.user.id).order_by(Transaction.created_at.desc())
        ).all()
        return render_template("customer_dashboard.html", transactions=transactions)

    @app.get("/profile")
    @permission_required("profile:view_own")
    def profile():
        return render_template("profile.html", user=g.user)

    @app.route("/profile/edit", methods=["GET", "POST"])
    @permission_required("profile:update_own")
    def profile_edit():
        if request.method == "GET":
            return render_template("profile_edit.html", values={
                "full_name": g.user.full_name, "email": g.user.email, "phone": g.user.phone})

        # Only the three fields below are read from the form. Role, username and status cannot be set here.
        data, errors = validation.validate_profile(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("profile_edit.html", values=request.form), 400

        changed = [k for k in ("full_name", "email", "phone") if getattr(g.user, k) != data[k]]
        for key in ("full_name", "email", "phone"):
            setattr(g.user, key, data[key])
        db.session.commit()
        audit("profile_updated", g.user.username, ",".join(changed) or "no change")
        flash("Your profile has been updated.", "success")
        return redirect(url_for("profile"))

    @app.get("/customers/<int:customer_id>")
    @permission_required()
    def customer_detail(customer_id):
        customer = load_customer_for_actor(customer_id)
        transactions = db.session.scalars(
            db.select(Transaction).filter_by(customer_id=customer.id).order_by(Transaction.created_at.desc())
        ).all()
        return render_template("customer_detail.html", customer=customer, transactions=transactions)

    # ------------------------------------------------------------------ manager routes
    @app.get("/manager/dashboard")
    @permission_required("customers:view")
    def manager_dashboard():
        customer_count = db.session.scalar(
            db.select(db.func.count(User.id)).join(Role).where(Role.name == "customer"))
        pending = db.session.scalar(
            db.select(db.func.count(Transaction.id)).where(Transaction.status == "pending"))
        approved = db.session.scalar(
            db.select(db.func.count(Transaction.id)).where(Transaction.status == "approved"))
        return render_template("manager_dashboard.html", customer_count=customer_count,
                               pending=pending, approved=approved)

    @app.get("/manager/customers")
    @permission_required("customers:view")
    def manager_customers():
        customers = db.session.scalars(
            db.select(User).join(Role).where(Role.name == "customer").order_by(User.id)).all()
        return render_template("manager_customers.html", customers=customers)

    @app.get("/manager/transactions")
    @permission_required("transactions:view")
    def manager_transactions():
        transactions = db.session.scalars(db.select(Transaction).order_by(Transaction.created_at.desc())).all()
        customers = db.session.scalars(
            db.select(User).join(Role).where(Role.name == "customer").order_by(User.id)).all()
        return render_template("manager_transactions.html", transactions=transactions, customers=customers)

    @app.post("/manager/transactions")
    @permission_required("transactions:manage")
    def manager_transaction_create():
        data, errors = validation.validate_transaction(request.form)
        customer = db.session.get(User, data["customer_id"]) if data["customer_id"] else None
        if customer is None or customer.role_name != "customer":
            errors.append("The selected customer does not exist.")
        if errors:
            for message in errors:
                flash(message, "error")
            return redirect(url_for("manager_transactions"))

        txn = Transaction(customer_id=customer.id, amount_cents=data["amount_cents"],
                          description=data["description"], status="pending", created_by=g.user.id)
        db.session.add(txn)
        db.session.commit()
        audit("transaction_created", f"transaction:{txn.id}", f"customer={customer.username}")
        flash("Transaction created and awaiting review.", "success")
        return redirect(url_for("manager_transactions"))

    @app.post("/manager/transactions/<int:txn_id>/status")
    @permission_required("transactions:manage")
    def manager_transaction_status(txn_id):
        txn = db.session.get(Transaction, txn_id)
        if txn is None:
            abort(404)
        new_status = request.form.get("status", "")
        if new_status not in {"approved", "rejected"}:
            abort(400)
        if txn.status != "pending":
            flash("Only pending transactions can be reviewed.", "error")
            return redirect(url_for("manager_transactions"))
        txn.status = new_status
        txn.reviewed_by = g.user.id
        db.session.commit()
        audit("transaction_" + new_status, f"transaction:{txn.id}")
        flash(f"Transaction {txn.id} {new_status}.", "success")
        return redirect(url_for("manager_transactions"))

    # ------------------------------------------------------------------ administrator routes
    @app.get("/admin/dashboard")
    @permission_required("users:manage")
    def admin_dashboard():
        user_count = db.session.scalar(db.select(db.func.count(User.id)))
        active_count = db.session.scalar(db.select(db.func.count(User.id)).where(User.is_active.is_(True)))
        role_count = db.session.scalar(db.select(db.func.count(Role.id)))
        recent = db.session.execute(
            db.select(AuditLog, User.username).outerjoin(User, AuditLog.actor_id == User.id)
            .order_by(AuditLog.id.desc()).limit(6)).all()
        return render_template("admin_dashboard.html", user_count=user_count, active_count=active_count,
                               role_count=role_count, recent=recent)

    @app.get("/admin/users")
    @permission_required("users:manage")
    def admin_users():
        users = db.session.scalars(db.select(User).order_by(User.id)).all()
        roles = db.session.scalars(db.select(Role).order_by(Role.id)).all()
        return render_template("admin_users.html", users=users, roles=roles)

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @permission_required("users:manage", "roles:assign")
    def admin_user_new():
        roles = db.session.scalars(db.select(Role).order_by(Role.id)).all()
        if request.method == "GET":
            return render_template("admin_user_new.html", roles=roles, values={})

        data, errors = validation.validate_new_user(request.form)
        role = db.session.scalar(db.select(Role).filter_by(name=data["role"]))
        if role is None:
            errors.append("Choose a valid role.")
        if db.session.scalar(db.select(User).filter_by(username=data["username"])) is not None:
            errors.append("That username is already taken.")
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("admin_user_new.html", roles=roles, values=request.form), 400

        user = User(username=data["username"], full_name=data["full_name"], email=data["email"],
                    phone=data["phone"], role=role)
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        audit("user_created", user.username, f"role={role.name}")
        flash(f"User '{user.username}' created as {role.label}.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/role")
    @permission_required("roles:assign")
    def admin_change_role(user_id):
        user = db.session.get(User, user_id)
        if user is None:
            abort(404)
        new_role = db.session.scalar(db.select(Role).filter_by(name=request.form.get("role", "")))
        if new_role is None:
            abort(400)
        if user.id == g.user.id:
            flash("You cannot change your own role.", "error")
            return redirect(url_for("admin_users"))
        old_role = user.role_name
        user.role = new_role
        db.session.commit()
        audit("role_changed", user.username, f"{old_role}->{new_role.name}")
        flash(f"{user.username} is now {new_role.label}.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/status")
    @permission_required("users:manage")
    def admin_toggle_status(user_id):
        user = db.session.get(User, user_id)
        if user is None:
            abort(404)
        if user.id == g.user.id:
            flash("You cannot deactivate your own account.", "error")
            return redirect(url_for("admin_users"))
        user.is_active = not user.is_active
        if not user.is_active:
            # Revoke all active sessions of a deactivated user immediately.
            for record in db.session.scalars(db.select(UserSession).filter_by(user_id=user.id)).all():
                record.revoked = True
        db.session.commit()
        audit("user_activated" if user.is_active else "user_deactivated", user.username)
        flash(f"{user.username} is now {'active' if user.is_active else 'inactive'}.", "success")
        return redirect(url_for("admin_users"))

    @app.get("/admin/roles")
    @permission_required("permissions:manage")
    def admin_roles():
        roles = db.session.scalars(db.select(Role).order_by(Role.id)).all()
        catalogue = db.session.scalars(db.select(Permission).order_by(Permission.name)).all()
        return render_template("admin_roles.html", roles=roles, catalogue=catalogue,
                               protected=PROTECTED_ADMIN_PERMISSIONS)

    @app.post("/admin/roles/<int:role_id>")
    @permission_required("permissions:manage")
    def admin_update_role_permissions(role_id):
        role = db.session.get(Role, role_id)
        if role is None:
            abort(404)
        requested = set(request.form.getlist("permissions"))
        if not requested <= set(PERMISSIONS):
            abort(400)
        if role.name == "admin" and not PROTECTED_ADMIN_PERMISSIONS <= requested:
            flash("Core administrator permissions cannot be removed (this would lock out administrators).",
                  "error")
            return redirect(url_for("admin_roles"))
        role.permissions = db.session.scalars(
            db.select(Permission).where(Permission.name.in_(requested))).all()
        db.session.commit()
        audit("permissions_changed", role.name, ",".join(sorted(requested)))
        flash(f"Permissions updated for {role.label}.", "success")
        return redirect(url_for("admin_roles"))

    @app.get("/admin/audit")
    @permission_required("users:manage")
    def admin_audit():
        rows = db.session.execute(
            db.select(AuditLog, User.username).outerjoin(User, AuditLog.actor_id == User.id)
            .order_by(AuditLog.id.desc()).limit(200)).all()
        return render_template("admin_audit.html", rows=rows)

    # ------------------------------------------------------------------ database & demo data
    with app.app_context():
        db.create_all()
        seed_database()
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=5000, debug=False)
