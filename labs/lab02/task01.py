import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

SESSION_TIMEOUT_SEC = 900
PBKDF2_ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 8

class User:
    def __init__(self, username: str, email: str, role: str, active: bool = True):
        self.username = username
        self.role = role
        self.active = active
        self.__email = email
        self.__password_hash: str = ""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        return self.__email

    @email.setter
    def email(self, value: str):
        pattern = r"^[a-zA-Z0-9._%+-]{3,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self.__email = value

    def set_password(self, password: str):
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Пароль занадто короткий. Мінімальна довжина: {MIN_PASSWORD_LENGTH}"
                " символів."
            )

        self.__password_salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS
        )
        self.__password_hash = pwd_hash.hex()

        return hmac.compare_digest(pwd_hash.hex(), self.__password_hash)

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(pwd_hash.hex(), self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return (
            f"User(username='{self.username}', email='{self.email}',"
            f" role='{self.role}', status='{status}')"
        )

class Admin(User): # Успадкування

    def __init__(
      self,
      username: str,
      email: str,
      role: str = "administrator",
      active: bool = True,
      permissions: list[str] | None = None,
    ):
     super().__init__(username, email, role, active)
     self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
      self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = (
            ", ".join(sorted(self.permissions))
            if self.permissions
            else "No permissions"
        )
        return super().__str__() + f" [Admin Permissions: {perms}]"

class Session:

    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Timeout has to be positive.")
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed <= timeout_sec

@dataclass
class AuditRecord:
    timestamp: str
    username: str
    action: str

class AuditLog:
    def __init__(self):
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        record = AuditRecord(timestamp=timestamp, username=username, action=action)
        self._records.append(record)

    def show_all(self):
        print("\n=== AUDIT LOG ===")
        if not self._records:
          print("[log is empty]")
          return
        for r in self._records:
          print(f"[{r.timestamp}] User: '{r.username}' -> Action: {r.action}")
        print("=================\n")

class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog): # Композиція
        self.user = user
        self.audit_log = audit_log
        self.session: Session | None = None

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure_inactive")
            print(f"[AUTH] Error: Account '{self.user.username}' is inactive.")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(self.user.username, "login_success")
            print(f"[AUTH] User '{self.user.username}' successfully logged from IP {ip}.")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure_wrong_password")
            print(
              f"[AUTH] Log attempt failed '{self.user.username}': wrong password."
          )
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        else:
            self.logout()
            return False

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            print(f"[AUTH] User session '{self.user.username}' is ended.")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "role":
            return self.user.role
        elif key == "email":
            return self.user.email
        raise KeyError(f"Unknown or forbidden key: '{key}'")

    def __setitem__(self, key: str, value):
        if key == "email":
            if not isinstance(value, str):
                raise TypeError("Email has to be string.")
            self.user.email = value
        elif key == "role":
            if not isinstance(value, str):
                raise TypeError("Role has to be string.")
            self.user.role = value
        else:
            raise KeyError(f"Attribute change '{key}' Is forbidden or unsupported.")