"""Users service backed by the ``users`` table (formerly ``users.json``).

Supports a registration + admin approval lifecycle:

* New self-registered accounts are created with ``status="pending"`` and are
  blocked from signing in until an administrator approves them.
* Administrators can approve/reject accounts, change roles, and create
  accounts on behalf of users (already approved).
"""

import threading
import time
import uuid

from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from database.db import get_session
from database.repositories import UsersRepository

_lock = threading.Lock()

ADMIN_ROLES = ("Admin",)

ASSIGNABLE_ROLES = ("Admin", "Security Analyst", "Viewer")

SIGNUP_ROLES = ("Security Analyst", "Viewer")

VALID_STATUS = ("pending", "approved", "rejected", "disabled")

ALLOWED_ROLES = ASSIGNABLE_ROLES


def _public(user):
    if not user:
        return None
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role or "",
        "status": user.status or "approved",
        "created": user.created,
    }


def _repo():
    return UsersRepository(get_session())


def is_admin_role(role):
    return (role or "") == "Admin"


def has_login_role(role):
    return (role or "").strip() in ALLOWED_ROLES


def role_label(role):
    text = (role or "").strip()
    return text if text else "No role assigned"


def find_by_email(email):
    return _repo().by_email(email)


def get_user(user_id):
    return _repo().get(user_id)


def public_user(user_id):
    return _public(get_user(user_id))


def list_users(status=None):
    if status:
        users = _repo().list_by_status(status)
    else:
        users = _repo().list_users()
    return [_public(user) for user in users]


def list_members():
    """Read-only roster for non-admin users: name and role only.

    No e-mail, status or account management fields are exposed so members can
    only see the platform's people directory.
    """
    return [
        {
            "id": user.id,
            "name": user.name,
            "role": user.role or "",
        }
        for user in _repo().list_users()
    ]


def list_admins():
    return [_public(user) for user in _repo().list_admins()]


def create_user(name, email, password, role=None, status="pending", user_id=None):
    """Create a user account.

    Registration defaults to ``status="pending"`` so the account cannot sign
    in until an administrator approves it. Administrators may create accounts
    directly with ``status="approved"``.
    """
    name = (name or "").strip()
    email = (email or "").strip().lower()
    password = password or ""
    role = (role or "").strip()

    if not name or not email or not password:
        raise ValueError("Name, email, and password are required.")
    if "@" not in email or "." not in email:
        raise ValueError("Enter a valid email address.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    if role and role not in ALLOWED_ROLES:
        raise ValueError(
            "Role must be one of: {0}.".format(", ".join(ALLOWED_ROLES))
        )
    if status not in VALID_STATUS:
        raise ValueError("Invalid account status.")

    with _lock:
        if find_by_email(email):
            raise ValueError("An account with this email already exists.")
        user = _repo().create(
            {
                "id": user_id or ("usr-" + uuid.uuid4().hex[:16]),
                "name": name,
                "email": email,
                "password_hash": generate_password_hash(password),
                "role": role,
                "status": status,
                "created": time.time(),
            }
        )

    return _public(user)


def authenticate(email, password):
    """Return the public user when the credentials are valid and approved."""
    user = find_by_email(email)
    if not user:
        return None
    if (user.status or "approved") != "approved":
        return None
    if not has_login_role(user.role):
        return None
    if not check_password_hash(user.password_hash or "", password or ""):
        return None
    return _public(user)


def status_for_email(email):
    """Return the account status for an email, or None when it does not exist."""
    user = find_by_email(email)
    if not user:
        return None
    if (user.status or "approved") == "approved" and not has_login_role(user.role):
        return "no_role"
    return user.status or "approved"


def set_status(user_id, status):
    """Approve/reject/disable an account (administrator action)."""
    if status not in VALID_STATUS:
        raise ValueError("Invalid account status.")
    with _lock:
        user = _repo().set_status(user_id, status)
    if user is None:
        raise ValueError("Account not found.")
    return _public(user)


def set_role(user_id, role):
    """Change an account's role (administrator action)."""
    role = (role or "").strip()
    if role not in ALLOWED_ROLES:
        raise ValueError(
            "Role must be one of: {0}.".format(", ".join(ALLOWED_ROLES))
        )
    with _lock:
        user = _repo().set_role(user_id, role)
    if user is None:
        raise ValueError("Account not found.")
    return _public(user)
