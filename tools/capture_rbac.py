"""Take browser screenshots of the RUNNING RBAC application (start `python app.py` first).

    python tools/capture_rbac.py

Each screenshot records the HTTP status returned by the server, written to Screenshots/RBAC/capture_log.txt.
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "Screenshots" / "RBAC"
BASE = "http://127.0.0.1:5000"
DEMO = {"customer": "Customer#2026", "manager": "Manager#2026", "admin": "Admin#2026"}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    log_lines = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1280, "height": 900}, device_scale_factor=2)
        page = context.new_page()

        def snap(name, path, note):
            response = page.goto(BASE + path, wait_until="load")
            page.screenshot(path=str(OUT / name), full_page=True)
            line = f"{name}\tGET {path}\tHTTP {response.status}\t{note}"
            log_lines.append(line)
            print(line)

        def login(username):
            page.goto(BASE + "/login", wait_until="load")
            page.fill("input[name=username]", username)
            page.fill("input[name=password]", DEMO[username])
            with page.expect_navigation(wait_until="load"):
                page.click("button[type=submit]")

        def logout():
            with page.expect_navigation(wait_until="load"):
                page.click("button:has-text('Log out')")

        # Unauthenticated
        snap("01_login_page.png", "/login", "login page, no session")
        snap("11_unauthenticated_request_401.png", "/customer/dashboard", "expected 401 without login")

        # Customer
        login("customer")
        snap("02_customer_dashboard.png", "/customer/dashboard", "expected 200")
        snap("03_customer_profile.png", "/profile", "expected 200 (own profile)")
        snap("04_customer_other_customer_record_denied.png", "/customers/2",
             "expected 404: customer 1 requests customer 2")
        snap("05_customer_admin_page_denied.png", "/admin/dashboard", "expected 403")
        logout()

        # Manager
        login("manager")
        snap("06_manager_dashboard.png", "/manager/dashboard", "expected 200")
        snap("12_manager_transactions.png", "/manager/transactions", "expected 200")
        snap("13_manager_admin_page_denied.png", "/admin/users", "expected 403: manager on admin page")
        logout()

        # Administrator
        login("admin")
        snap("07_admin_dashboard.png", "/admin/dashboard", "expected 200")
        snap("08_admin_user_and_role_management.png", "/admin/users", "expected 200")
        snap("09_admin_roles_and_permissions.png", "/admin/roles", "expected 200")
        snap("10_admin_audit_log.png", "/admin/audit", "expected 200")
        logout()

        browser.close()

    (OUT / "capture_log.txt").write_text(
        "Screenshot\tRequest\tServer response\tNote\n" + "\n".join(log_lines) + "\n", encoding="utf-8")
    print("Wrote", OUT / "capture_log.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
