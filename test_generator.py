"""Тесты generator.py (запуск: python -m unittest -v)."""
import string
import unittest

import generator as g


class GenerationTests(unittest.TestCase):
    def test_length(self):
        for n in (4, 8, 16, 64, 128):
            self.assertEqual(len(g.generate_password(g.PasswordOptions(length=n))), n)

    def test_contains_every_selected_type(self):
        for _ in range(200):
            p = g.generate_password(g.PasswordOptions(length=8))
            self.assertTrue(any(c in string.ascii_lowercase for c in p))
            self.assertTrue(any(c in string.ascii_uppercase for c in p))
            self.assertTrue(any(c in string.digits for c in p))
            self.assertTrue(any(c in g.SPECIAL for c in p))

    def test_only_digits(self):
        p = g.generate_password(g.PasswordOptions(
            length=20, use_lower=False, use_upper=False, use_special=False))
        self.assertTrue(p.isdigit())

    def test_exclude_ambiguous(self):
        for _ in range(100):
            p = g.generate_password(g.PasswordOptions(length=40, exclude_ambiguous=True))
            self.assertFalse(set(p) & set(g.AMBIGUOUS))

    def test_no_pools_raises(self):
        with self.assertRaises(ValueError):
            g.generate_password(g.PasswordOptions(
                use_lower=False, use_upper=False, use_digits=False, use_special=False))

    def test_bad_length_raises(self):
        for n in (0, 3, 129):
            with self.assertRaises(ValueError):
                g.generate_password(g.PasswordOptions(length=n))

    def test_passwords_differ(self):
        self.assertEqual(len({g.generate_password() for _ in range(50)}), 50)


class EvaluationTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(g.evaluate_password("").score, 0)

    def test_common_password_is_very_weak(self):
        self.assertEqual(g.evaluate_password("password").level, "Очень слабый")

    def test_common_password_with_tail_or_leet_is_weak(self):
        for p in ("Password1!", "P@ssw0rd2024", "qwerty123!", "Admin2024"):
            self.assertLessEqual(g.evaluate_password(p).score, 20, p)

    def test_random_password_is_not_flagged_as_common(self):
        r = g.evaluate_password("Xk9#mQ2$vL5!")
        self.assertFalse(any("популярных" in h for h in r.hints))

    def test_sequence_and_repeat_penalty(self):
        plain = g.evaluate_password("Xk9#mQ2$")
        seq = g.evaluate_password("Abc123!!")
        self.assertLess(seq.effective_entropy, seq.entropy)
        self.assertEqual(plain.effective_entropy, plain.entropy)

    def test_longer_is_stronger(self):
        self.assertGreater(g.evaluate_password("aB3$aB3$xY7&pQ1!").score,
                           g.evaluate_password("aB3$xY7&").score)

    def test_generated_long_password_is_strong(self):
        p = g.generate_password(g.PasswordOptions(length=24))
        self.assertIn(g.evaluate_password(p).level, ("Хороший", "Отличный"))

    def test_only_digits_hint(self):
        r = g.evaluate_password("48151623")
        self.assertTrue(any("только из цифр" in h for h in r.hints))

    def test_score_range(self):
        for p in ("a", "123", "Tr0ub4dor&3", "x" * 200):
            self.assertTrue(0 <= g.evaluate_password(p).score <= 100)


if __name__ == "__main__":
    unittest.main()
