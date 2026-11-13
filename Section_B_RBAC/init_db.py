"""Initialise the SQLite database and seed demo data.

    python init_db.py           # create tables and demo accounts (safe to run more than once)
    python init_db.py --reset   # DELETE all data, then recreate tables and demo accounts
"""
import argparse

from app import create_app
from extensions import db


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="drop all tables first (deletes data)")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.reset:
            db.drop_all()
            db.create_all()
            from seed import seed_database
            seed_database()
            print("Database reset and seeded.")
        else:
            print("Database initialised (tables present, demo data seeded if empty).")
        print("Database file:", app.config["SQLALCHEMY_DATABASE_URI"])


if __name__ == "__main__":
    main()
