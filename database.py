"""SQLite: пользователи и журнал их паролей.

Таблицы:
    users(username, salt, key_check)      — имя пользователя и проверка его ключа
    passwords(username, resource, ...)    — журнал паролей (по одной записи на ресурс)

Сам ключ пользователя нигде не хранится: в key_check лежит зашифрованная
этим ключом контрольная строка. Пароли шифруются Fernet, ключ шифрования
выводится из ключа пользователя через PBKDF2-HMAC-SHA256 с индивидуальной солью.
"""

import base64
import os
import sqlite3
from datetime import datetime
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_DB_FILE = "passwords.db"
KDF_ITERATIONS = 480_000
MIN_KEY_LENGTH = 8
MAX_NAME_LENGTH = 64
CHECK_TEXT = b"key-ok"


class DatabaseError(Exception):
    """Ошибка работы с базой (неверный ключ, пользователь не выбран и т.д.)."""


def _derive_key(key: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(key.encode("utf-8")))


def _clean(value: str, what: str) -> str:
    value = value.strip()
    if not value:
        raise DatabaseError(f"{what} не может быть пустым.")
    if len(value) > MAX_NAME_LENGTH:
        raise DatabaseError(f"{what}: не более {MAX_NAME_LENGTH} символов.")
    return value


class Database:
    def __init__(self, db_name: str = DEFAULT_DB_FILE):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.username: Optional[str] = None
        self._fernet: Optional[Fernet] = None
        self.create_tables()

    def create_tables(self) -> None:
        """Создание таблиц, если они не существуют"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                salt TEXT NOT NULL,
                key_check TEXT NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                username TEXT NOT NULL COLLATE NOCASE,
                resource TEXT NOT NULL COLLATE NOCASE,
                password_enc TEXT NOT NULL,
                updated_date TEXT NOT NULL,
                PRIMARY KEY (username, resource)
            )
        ''')
        self.conn.commit()

    # ------------------------------------------------------------------
    # Пользователи
    # ------------------------------------------------------------------
    def login(self, username: str, key: str) -> bool:
        """Вход или создание пользователя.

        Пользователя с таким именем нет — создаётся новый (True).
        Есть и ключ верный — вход (False).
        Есть, но ключ неверный — ошибка: имя пользователя должно быть уникальным.
        """
        name = _clean(username, "Имя пользователя")
        self.cursor.execute(
            "SELECT username, salt, key_check FROM users WHERE username = ?", (name,))
        row = self.cursor.fetchone()

        if row is None:
            if len(key) < MIN_KEY_LENGTH:
                raise DatabaseError(
                    f"Ключ нового пользователя — не короче {MIN_KEY_LENGTH} символов.")
            salt = os.urandom(16)
            fernet = Fernet(_derive_key(key, salt))
            self.cursor.execute(
                "INSERT INTO users (username, salt, key_check) VALUES (?, ?, ?)",
                (name, base64.b64encode(salt).decode("ascii"),
                 fernet.encrypt(CHECK_TEXT).decode("ascii")))
            self.conn.commit()
            created = True
        else:
            name, salt_b64, key_check = row
            fernet = Fernet(_derive_key(key, base64.b64decode(salt_b64)))
            try:
                ok = fernet.decrypt(key_check.encode("ascii")) == CHECK_TEXT
            except InvalidToken:
                ok = False
            if not ok:
                raise DatabaseError(
                    f"Пользователь «{name}» уже существует, но ключ неверный.")
            created = False

        self.username, self._fernet = name, fernet
        return created

    def _require_login(self) -> Fernet:
        if self._fernet is None or self.username is None:
            raise DatabaseError("Сначала войдите: укажите имя пользователя и ключ.")
        return self._fernet

    # ------------------------------------------------------------------
    # Журнал паролей текущего пользователя
    # ------------------------------------------------------------------
    def resource_exists(self, resource: str) -> bool:
        """Есть ли у пользователя пароль для этого ресурса"""
        self._require_login()
        self.cursor.execute(
            "SELECT 1 FROM passwords WHERE username = ? AND resource = ?",
            (self.username, resource.strip()))
        return self.cursor.fetchone() is not None

    def save_password(self, resource: str, password: str) -> bool:
        """Сохраняет пароль ресурса. True — существующая запись обновлена, False — добавлена"""
        fernet = self._require_login()
        resource = _clean(resource, "Название ресурса")
        token = fernet.encrypt(password.encode("utf-8")).decode("ascii")
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        if self.resource_exists(resource):
            self.cursor.execute('''
                UPDATE passwords SET password_enc = ?, updated_date = ?
                WHERE username = ? AND resource = ?
            ''', (token, now, self.username, resource))
            updated = True
        else:
            self.cursor.execute('''
                INSERT INTO passwords (username, resource, password_enc, updated_date)
                VALUES (?, ?, ?, ?)
            ''', (self.username, resource, token, now))
            updated = False
        self.conn.commit()
        return updated

    def get_journal(self) -> List[Tuple[str, str, str]]:
        """Журнал пользователя: [(ресурс, пароль, дата изменения)]"""
        fernet = self._require_login()
        self.cursor.execute('''
            SELECT resource, password_enc, updated_date FROM passwords
            WHERE username = ? ORDER BY resource
        ''', (self.username,))
        try:
            return [(res, fernet.decrypt(tok.encode("ascii")).decode("utf-8"), date)
                    for res, tok, date in self.cursor.fetchall()]
        except InvalidToken as exc:
            raise DatabaseError("Не удалось расшифровать запись журнала.") from exc

    def delete_password(self, resource: str) -> bool:
        """Удаляет запись журнала"""
        self._require_login()
        self.cursor.execute(
            "DELETE FROM passwords WHERE username = ? AND resource = ?",
            (self.username, resource))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def close(self) -> None:
        """Закрытие соединения с базой данных"""
        self._fernet = None
        self.conn.close()
