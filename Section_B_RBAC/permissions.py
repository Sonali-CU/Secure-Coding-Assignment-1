"""Permission catalogue and role definitions (least privilege).

Authorisation decisions are always made on the server by checking these permission names
against the role stored in the database. Nothing about roles is read from the client.
"""
from extensions import db
from models import Permission, Role

PERMISSIONS = {
    "profile:view_own": "View own profile",
    "profile:update_own": "Update own profile",
    "transactions:view_own": "View own transactions",
    "customers:view": "View customer records",
    "transactions:view": "View all transactions",
    "transactions:manage": "Create, approve and reject transactions",
    "users:manage": "Create, activate and deactivate users; view audit log",
    "roles:assign": "Assign roles to users",
    "permissions:manage": "Change the permissions granted to each role",
}

ROLE_DEFINITIONS = {
    "customer": ("Customer", ["profile:view_own", "profile:update_own", "transactions:view_own"]),
    "manager": ("Manager", ["customers:view", "transactions:view", "transactions:manage"]),
    "admin": ("Administrator", ["users:manage", "roles:assign", "permissions:manage"]),
}

# Cannot be removed from the admin role, otherwise the last administrator could lock everyone out.
PROTECTED_ADMIN_PERMISSIONS = frozenset({"users:manage", "roles:assign", "permissions:manage"})


def seed_roles_and_permissions():
    """Create the permission catalogue and the three roles. Idempotent."""
    for name, description in PERMISSIONS.items():
        if db.session.scalar(db.select(Permission).filter_by(name=name)) is None:
            db.session.add(Permission(name=name, description=description))
    db.session.flush()

    for role_name, (label, permission_names) in ROLE_DEFINITIONS.items():
        role = db.session.scalar(db.select(Role).filter_by(name=role_name))
        if role is None:
            role = Role(name=role_name, label=label)
            db.session.add(role)
            db.session.flush()
            role.permissions = [
                db.session.scalar(db.select(Permission).filter_by(name=p)) for p in permission_names
            ]
    db.session.commit()
