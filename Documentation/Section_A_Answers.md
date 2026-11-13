# Section A: Authorization and Access Control

**Scenario: Online banking application.** Customers view account details, transfer money, download statements and update personal information. Administrators manage users, view transactions and modify account settings. Recent problems: customers could read other customers' account details by changing account IDs in the URL, and some users reached administrative pages by modifying client-side code.

The answers below refer to the implementation in `Section_B_RBAC/` so that each control can be checked in code and in the test suite (`Section_B_RBAC/tests/test_rbac.py`).

---

## 1. Deny-access-by-default

**Answer.** Every request must pass one gate before any route runs. In the application, `deny_by_default()` in `app.py` loads the current user from the server-side session and aborts with **401** unless the endpoint is on an explicit public list (`index`, `login`, `health`, `static`). A new route added by a developer is therefore protected automatically. The developer must make a conscious decision to make it public. On top of the gate, each protected route declares the permissions it needs with `@permission_required(...)`. Permissions are granted, never inferred, so a missing grant means access is denied (**403**).

**Evidence.** `test_unauthenticated_requests_get_401` checks 14 URLs, including a non-existent route, and gets 401 for each.

## 2. Server-side authorization for transactions

**Answer.** The server alone decides whether a transaction happens. A transaction is created or reviewed only after the server has checked:

1. the caller is authenticated (session record valid, account active);
2. the caller holds `transactions:manage` (managers only, not customers or administrators);
3. the input is valid (customer exists and has the customer role, amount between 0.01 and 100,000.00 in two decimal places, safe description);
4. the state transition is allowed (only `pending` transactions can be approved or rejected).

Client-side checks such as hiding a button or validating in JavaScript are only usability features. Anyone can send a request directly. For a production system, transfers should also carry an idempotency key so a retried request cannot execute twice, and high-value transfers should require step-up verification (a one-time code).

**Evidence.** `test_customer_cannot_create_or_review_transactions_403`, `test_manager_creates_transaction`, `test_amount_validation_rejects_negative_amount`, `test_amount_validation_rejects_nan`.

## 3. Least privilege for customers, employees and administrators

**Answer.** Each role receives only the permissions its job needs (`Section_B_RBAC/permissions.py`):

| Role | Permissions | Deliberately excluded |
|---|---|---|
| Customer | view own profile, update own profile, view own transactions | any other customer's data, manager and admin pages |
| Manager | view customer records, view all transactions, create and approve/reject transactions | user administration, role assignment, permission changes, own-profile edits |
| Administrator | manage users, assign roles, manage role permissions, view audit log | transaction review and customer financial data (separation of duties) |

The separation between transaction handling and user administration means that one compromised administrator account cannot both move money and grant itself more rights. At the infrastructure level the database account should also be limited to the operations the application needs.

**Evidence.** `test_admin_has_no_transaction_access_least_privilege`, `test_manager_cannot_manage_users_403`, `test_customer_cannot_access_manager_pages_403`.

## 4. Authorization verified for every protected resource and action

**Answer.** Checks are centralised so they cannot be forgotten or written inconsistently:

- **Function level:** `@permission_required(...)` on every protected route. It returns 401 when there is no user and 403 when a permission is missing. Each denial is written to the audit log.
- **Object level:** `load_customer_for_actor()` in `auth.py` is the single place that decides whether a customer record may be read. It is used by every route that takes a customer ID.
- **Coverage:** the test suite exercises protected routes with each role, and a dedicated test removes a permission from a role and confirms the change takes effect on the next request.
- **Review:** the route table in `Documentation/Implementation_Explanation.md` lists every route and its required permission, so reviewers can compare the code with the policy.

## 5. Preventing unauthorized access by modifying browser-side JavaScript or HTML

**Answer.** The browser is untrusted. The role is never read from the page, from JavaScript, from a hidden field or from a request header. The server:

- identifies the user with a random session identifier stored in the database (the cookie carries only that identifier);
- reads the user's role and permissions from the database on every request;
- ignores all role-like values sent by the client: a hidden `role` field in the profile form, an `X-Role` header and a forged cookie all have no effect;
- ignores fields that are not on the allow-list when updating a profile, so mass assignment cannot set a role or an active flag;
- uses the same checks whether the request came from the page's own button or from a crafted request.

Hidden menu items and disabled buttons (for example the admin links in the navigation bar) are shown only to be helpful. Removing them would not change what the server allows.

**Evidence.** `test_customer_updates_only_own_profile_fields`, `test_forged_role_header_is_ignored`, `test_forged_session_cookie_is_rejected`.

## 6. Preventing one customer from viewing or modifying another customer's account (IDOR)

**Answer.** The ID in the URL is treated as a request, not as proof of ownership:

- Customer routes take their record from the logged-in session, not from the URL. The profile edit page has no ID parameter at all.
- Where a route does take an ID (`/customers/<id>`), `load_customer_for_actor()` allows access only when the ID equals the logged-in user's ID or the caller holds `customers:view`.
- A customer who asks for another customer's record receives **404**, the same response as for an ID that does not exist. An attacker therefore cannot enumerate valid account numbers. (The assignment allows either 403 or 404. This project uses 404 for customers and records the decision in the README.)
- Each attempt is written to the audit log (`idor_blocked`).
- As defence in depth, production systems should use non-sequential identifiers (UUIDs), rate-limit requests that fail authorization, and alert on repeated attempts.

**Evidence.** `test_customer_cannot_view_another_customer_404`, `test_customer_404_is_identical_for_existing_and_missing_records`, `test_customer_cannot_edit_another_customers_profile`.

## 7. Protecting administrative functionality

**Answer.** Administrative pages are under `/admin/` and each requires a specific permission. Additional controls:

- Customers and managers receive **403** on every administrative page and on every administrative action.
- Role changes and permission changes are validated against the known role list and the permission catalogue; unknown values are rejected with 400.
- An administrator cannot change their own role or deactivate their own account. This prevents accidental or malicious lock-out.
- Core administrator permissions (`users:manage`, `roles:assign`, `permissions:manage`) cannot be removed from the administrator role, which prevents the last administrator being removed by mistake.
- Every administrative change (user created, role changed, account activated or deactivated, permissions changed) is written to the audit log with the actor and the time.
- Production recommendations: multi-factor authentication for administrators, restricting admin pages to an internal network or VPN, re-authentication before sensitive changes, and a second approver for role changes.

**Evidence.** `test_customer_cannot_access_admin_pages_403`, `test_manager_cannot_change_permissions_403`, `test_unauthorized_role_modification_rejected_for_customer`, `test_admin_cannot_change_own_role`, `test_admin_cannot_remove_core_admin_permissions`.

## 8. Verifying resource ownership before updating account details or transferring funds

**Answer.** Before any update, the server loads the record and checks that it belongs to the caller:

- **Profile update:** the record loaded is always `current_user`. The form cannot name another user.
- **Transaction creation:** the source account must be a customer account; the manager acts on behalf of the bank, which is authorised by `transactions:manage`.
- **Transfers by customers** (not implemented in this demo, but the rule would be): the source account must satisfy `account.owner_id == session_user.id` before the debit is attempted, the destination must exist and be active, and the amount must not exceed the balance. Ownership is checked in the same database transaction as the debit, so a race cannot bypass it.
- **CSRF:** every state-changing form carries a token (Flask-WTF), and session cookies use `SameSite=Strict`, so a malicious site cannot trigger an update using the customer's browser.

**Evidence.** `test_customer_updates_only_own_profile_fields`, `test_state_changing_form_requires_csrf_token`.

## 9. Regular review of user roles and privilege assignments

**Answer.** Access should be reviewed on a schedule (for example quarterly) and after any staff change. The application supports the review:

1. **Inventory:** `/admin/users` lists every account with its role and status; `/admin/roles` shows the permission matrix.
2. **Audit trail:** `/admin/audit` shows logins, failed logins, denied access attempts, profile changes, role changes and permission changes. Denied attempts can reveal probing.
3. **Clean-up:** deactivate accounts that are no longer used (deactivation revokes active sessions immediately); change roles to match current duties; remove permissions that a role no longer needs.
4. **Process:** the reviewer exports the list, confirms each person's role with their line manager, records the decision, and keeps the evidence. Elevated access should be time-limited, with an explicit end date and a reminder to remove it.
5. **Automation (recommended):** a scheduled report that flags administrators, accounts with no login for 90 days, and roles whose permissions changed in the last month.

**Evidence.** `test_admin_deactivation_revokes_sessions`, `test_removing_customer_permission_takes_effect_immediately`, and the audit log rows written by the tests.
