"""Seed roles, permissions and DEVELOPMENT-ONLY demo accounts.

The demo passwords below are published in the README on purpose so markers can log in.
They must never be used outside local development. Change them or disable seeding for any real use.
"""
from decimal import Decimal

from extensions import db
from models import Role, Transaction, User
from permissions import seed_roles_and_permissions

DEMO_USERS = [
    {"username": "customer", "password": "Customer#2026", "role": "customer",
     "full_name": "Alice Customer", "email": "alice@example.test", "phone": "+1 555 0101"},
    {"username": "customer2", "password": "Customer2#2026", "role": "customer",
     "full_name": "Bob Customer", "email": "bob@example.test", "phone": "+1 555 0102"},
    {"username": "manager", "password": "Manager#2026", "role": "manager",
     "full_name": "Mary Manager", "email": "mary@example.test", "phone": "+1 555 0201"},
    {"username": "admin", "password": "Admin#2026", "role": "admin",
     "full_name": "Ann Administrator", "email": "ann@example.test", "phone": "+1 555 0301"},
]


def seed_database():
    """Idempotent: roles are created once; demo users and transactions only if no users exist."""
    seed_roles_and_permissions()
    if db.session.scalar(db.select(User.id).limit(1)) is not None:
        return

    for spec in DEMO_USERS:
        role = db.session.scalar(db.select(Role).filter_by(name=spec["role"]))
        user = User(username=spec["username"], full_name=spec["full_name"], email=spec["email"],
                    phone=spec["phone"], role=role)
        user.set_password(spec["password"])
        db.session.add(user)
    db.session.flush()

    customer = db.session.scalar(db.select(User).filter_by(username="customer"))
    customer2 = db.session.scalar(db.select(User).filter_by(username="customer2"))
    db.session.add_all([
        Transaction(customer_id=customer.id, amount_cents=25000, description="Salary deposit",
                    status="approved", created_by=customer.id),
        Transaction(customer_id=customer.id, amount_cents=4599, description="Online purchase",
                    status="pending", created_by=customer.id),
        Transaction(customer_id=customer2.id, amount_cents=9000, description="Utility payment",
                    status="pending", created_by=customer2.id),
    ])
    db.session.commit()
