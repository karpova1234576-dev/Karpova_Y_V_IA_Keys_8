"""Тесты database.py (запуск: python -m unittest -v)."""
import os
import tempfile
import unittest

from database import Database, DatabaseError

KEY = "correct-horse"


class UserTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")

    def tearDown(self):
        self.db.close()

    def test_new_user_is_created_then_logged_in(self):
        self.assertTrue(self.db.login("ivan", KEY))      # создан
        self.assertFalse(self.db.login("ivan", KEY))     # уже есть — вход

    def test_wrong_key_for_existing_user(self):
        self.db.login("ivan", KEY)
        with self.assertRaises(DatabaseError):
            self.db.login("ivan", "another-key-1")

    def test_username_is_unique_case_insensitive(self):
        self.db.login("Ivan", KEY)
        with self.assertRaises(DatabaseError):
            self.db.login("IVAN", "another-key-1")       # занято, ключ не тот
        self.assertFalse(self.db.login("IVAN", KEY))     # тот же пользователь
        self.assertEqual(self.db.username, "Ivan")
        count = self.db.cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(count, 1)

    def test_short_key_and_empty_name_rejected(self):
        with self.assertRaises(DatabaseError):
            self.db.login("ivan", "short")
        with self.assertRaises(DatabaseError):
            self.db.login("   ", KEY)
        self.assertEqual(self.db.cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_key_is_not_stored_in_plain_text(self):
        self.db.login("ivan", KEY)
        row = self.db.cursor.execute("SELECT * FROM users").fetchone()
        self.assertNotIn(KEY, " ".join(row))

    def test_requires_login(self):
        for call in (lambda: self.db.get_journal(),
                     lambda: self.db.save_password("a", "b"),
                     lambda: self.db.resource_exists("a"),
                     lambda: self.db.delete_password("a")):
            with self.assertRaises(DatabaseError):
                call()


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.db.login("ivan", KEY)

    def tearDown(self):
        self.db.close()

    def test_save_and_read(self):
        self.assertFalse(self.db.save_password("github.com", "Пароль-123!"))
        journal = self.db.get_journal()
        self.assertEqual([(r, p) for r, p, _ in journal], [("github.com", "Пароль-123!")])

    def test_password_is_encrypted_in_db(self):
        self.db.save_password("mail", "SecretValue123")
        raw = self.db.cursor.execute("SELECT password_enc FROM passwords").fetchone()[0]
        self.assertNotIn("SecretValue123", raw)

    def test_resource_is_unique_and_update_replaces(self):
        self.db.save_password("Mail", "old")
        self.assertTrue(self.db.resource_exists("mail"))          # без учёта регистра
        self.assertTrue(self.db.save_password("MAIL", "new"))     # True = обновлено
        journal = self.db.get_journal()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0][1], "new")

    def test_empty_resource_rejected(self):
        with self.assertRaises(DatabaseError):
            self.db.save_password("  ", "x")

    def test_delete(self):
        self.db.save_password("a", "1")
        self.assertTrue(self.db.delete_password("a"))
        self.assertFalse(self.db.delete_password("a"))
        self.assertEqual(self.db.get_journal(), [])

    def test_journals_are_isolated_between_users(self):
        self.db.save_password("mail", "ivan-secret")
        self.db.login("petr", "petrs-own-key")
        self.assertEqual(self.db.get_journal(), [])                # чужого журнала не видно
        self.db.save_password("mail", "petr-secret")               # тот же ресурс — другой пользователь
        self.assertEqual(self.db.get_journal()[0][1], "petr-secret")
        self.db.login("ivan", KEY)
        self.assertEqual(self.db.get_journal()[0][1], "ivan-secret")

    def test_other_users_key_cannot_decrypt(self):
        """Записи Ивана зашифрованы его ключом: ключ Петра их не расшифрует."""
        self.db.save_password("mail", "ivan-secret")
        raw = self.db.cursor.execute("SELECT password_enc FROM passwords").fetchone()[0]
        self.db.login("petr", "petrs-own-key")
        from cryptography.fernet import InvalidToken
        with self.assertRaises(InvalidToken):
            self.db._fernet.decrypt(raw.encode("ascii"))


class PersistenceTests(unittest.TestCase):
    def test_data_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.db")
            db = Database(path)
            db.login("ivan", KEY)
            db.save_password("mail", "secret-1")
            db.close()

            db = Database(path)
            self.assertFalse(db.login("ivan", KEY))
            self.assertEqual(db.get_journal()[0][:2], ("mail", "secret-1"))
            db.close()


if __name__ == "__main__":
    unittest.main()
