"""Database models. All access goes through the SQLAlchemy ORM (parameterised queries)."""
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow():
    """Naive UTC timestamp (SQLite stores naive datetimes)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


role_permissions = db.Table(
    "role_permissions",
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("permission_id", db.Integer, db.ForeignKey("permissions.id", ondelete="CASCADE"),
              primary_key=True),
)


class Permission(db.Model):
    __tablename__ = "permissions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False, default="")


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)     # customer | manager | admin
    label = db.Column(db.String(64), nullable=False)
    permissions = db.relationship("Permission", secondary=role_permissions, lazy="selectin")

    def has(self, permission_name):
        return any(p.name == permission_name for p in self.permissions)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Role", lazy="joined")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)   # Werkzeug: scrypt with random salt

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def role_name(self):
        return self.role.name

    def has_permission(self, permission_name):
        """Permissions are read from the database on every request, so role changes apply at once."""
        return self.role is not None and self.role.has(permission_name)


class Transaction(db.Model):
    __tablename__ = "transactions"
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    amount_cents = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")   # pending | approved | rejected
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    customer = db.relationship("User", foreign_keys="Transaction.customer_id")

    @property
    def amount_display(self):
        return f"{self.amount_cents / 100:,.2f}"


class UserSession(db.Model):
    """Server-side session record. The browser cookie only carries this random id."""
    __tablename__ = "user_sessions"
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=utcnow)
    revoked = db.Column(db.Boolean, nullable=False, default=False)


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(120), nullable=False, default="")
    detail = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
