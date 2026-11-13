"""Authentication, server-side sessions, permission decorators and ownership checks."""
import secrets
from datetime import timedelta
from functools import wraps

from flask import abort, current_app, g, request, session

from extensions import db
from models import AuditLog, User, UserSession, utcnow

SESSION_KEY = "sid"
TOUCH_INTERVAL = timedelta(seconds=30)   # limit database writes for last_seen updates


def audit(action, target="", detail=""):
    """Write an audit record. The actor is the current user, if any."""
    actor = g.get("user")
    db.session.add(AuditLog(
        actor_id=actor.id if actor else None,
        action=action[:80],
        target=str(target)[:120],
        detail=str(detail)[:255],
        created_at=utcnow(),
    ))
    db.session.commit()


def start_session(user):
    """Create a fresh server-side session after successful login (prevents session fixation)."""
    session.clear()
    sid = secrets.token_urlsafe(32)
    now = utcnow()
    db.session.add(UserSession(id=sid, user_id=user.id, created_at=now, last_seen=now))
    db.session.commit()
    session.permanent = True                 # applies PERMANENT_SESSION_LIFETIME (absolute timeout)
    session[SESSION_KEY] = sid


def end_session():
    """Revoke the server-side session and clear the cookie."""
    sid = session.get(SESSION_KEY)
    if sid:
        record = db.session.get(UserSession, sid)
        if record is not None:
            record.revoked = True
            db.session.commit()
    session.clear()


def load_current_user():
    """Resolve the logged-in user from the server-side session record.

    Returns None (and clears the cookie) for missing, revoked, idle-expired, absolutely expired
    or inactive-account sessions. This is the single place where a request becomes 'authenticated'.
    """
    sid = session.get(SESSION_KEY)
    if not sid:
        return None
    record = db.session.get(UserSession, sid)
    if record is None or record.revoked:
        session.clear()
        return None

    now = utcnow()
    idle_limit = timedelta(minutes=current_app.config["SESSION_IDLE_MINUTES"])
    absolute_limit = timedelta(hours=current_app.config["SESSION_ABSOLUTE_HOURS"])
    if now - record.last_seen > idle_limit or now - record.created_at > absolute_limit:
        record.revoked = True
        db.session.commit()
        session.clear()
        return None

    user = db.session.get(User, record.user_id)
    if user is None or not user.is_active:
        record.revoked = True
        db.session.commit()
        session.clear()
        return None

    if now - record.last_seen > TOUCH_INTERVAL:
        record.last_seen = now               # sliding idle window
        db.session.commit()
    return user


def permission_required(*permission_names):
    """Decorator: user must be authenticated AND hold every listed permission (403 otherwise)."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = g.get("user")
            if user is None:
                abort(401)
            missing = [p for p in permission_names if not user.has_permission(p)]
            if missing:
                audit("access_denied", request.path, "missing=" + ",".join(missing))
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def load_customer_for_actor(customer_id):
    """Object-level authorisation for customer records.

    * A customer may only load their own record.
    * A manager (customers:view) may load any customer record.
    * Anyone else is refused. Customers receive 404 for another customer's record, so an
      attacker cannot tell whether that ID exists.
    """
    actor = g.user
    customer = db.session.get(User, customer_id)
    exists = customer is not None and customer.role_name == "customer"

    if exists and actor.id == customer.id and actor.has_permission("profile:view_own"):
        return customer
    if exists and actor.has_permission("customers:view"):
        return customer

    if actor.role_name == "customer":
        audit("idor_blocked", f"customer:{customer_id}")
        abort(404)
    if not actor.has_permission("customers:view"):
        abort(403)
    abort(404)
