"""Users repository (table ``users``, formerly ``users.json``)."""

from database.models import User
from database.repositories.base import BaseRepository


class UsersRepository(BaseRepository):
    model = User

    def by_email(self, email):
        email = (email or "").strip().lower()
        return (
            self.session.query(User)
            .filter(User.email == email)
            .first()
        )

    def list_users(self):
        return (
            self.session.query(User)
            .order_by(User.created.desc())
            .all()
        )

    def list_by_status(self, status):
        return (
            self.session.query(User)
            .filter(User.status == status)
            .order_by(User.created.desc())
            .all()
        )

    def list_admins(self):
        return (
            self.session.query(User)
            .filter(User.role == "Admin")
            .all()
        )

    def create(self, data):
        user = User(
            id=data.get("id"),
            name=data.get("name"),
            email=(data.get("email") or "").strip().lower(),
            password_hash=data.get("password_hash"),
            role=data.get("role") or "",
            status=data.get("status") or "approved",
            created=data.get("created"),
        )
        self.session.add(user)
        self.session.commit()
        return user

    def set_status(self, user_id, status):
        user = self.session.get(User, user_id)
        if user is None:
            return None
        user.status = status
        self.session.commit()
        return user

    def set_role(self, user_id, role):
        user = self.session.get(User, user_id)
        if user is None:
            return None
        user.role = role
        self.session.commit()
        return user

    def backfill_null_status(self, default="approved"):
        result = (
            self.session.query(User)
            .filter(User.status.is_(None))
            .update({User.status: default}, synchronize_session=False)
        )
        self.session.commit()
        return int(result or 0)
