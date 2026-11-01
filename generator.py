"""Генерация паролей и оценка их сложности (без GUI и без хранилища)."""

import math
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{};:,.<>?/"
AMBIGUOUS = "Il1O0o"

MIN_LENGTH = 4
MAX_LENGTH = 128

# Небольшой список самых популярных паролей (в нижнем регистре)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "qwerty123",
    "111111", "abc123", "iloveyou", "admin", "welcome", "monkey", "dragon",
    "letmein", "login", "passw0rd", "p@ssw0rd", "football", "1q2w3e4r",
    "qazwsx", "zaq12wsx", "пароль", "йцукен",
}
# замены вида p@ssw0rd -> password
_LEET = str.maketrans({"@": "a", "4": "a", "$": "s", "5": "s",
                       "0": "o", "3": "e", "1": "i", "!": "i"})
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
                 "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю"]

# (порог эффективной энтропии в битах, название уровня)
LEVELS = [
    (28, "Очень слабый"),
    (40, "Слабый"),
    (60, "Средний"),
    (80, "Хороший"),
    (math.inf, "Отличный"),
]


# ---------------------------------------------------------------------------
# Генерация паролей
# ---------------------------------------------------------------------------
@dataclass
class PasswordOptions:
    """Параметры генерации пароля."""

    length: int = 16
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False


def _active_pools(options: PasswordOptions) -> List[str]:
    """Возвращает список наборов символов, выбранных пользователем."""
    pools = []
    if options.use_lower:
        pools.append(LOWERCASE)
    if options.use_upper:
        pools.append(UPPERCASE)
    if options.use_digits:
        pools.append(DIGITS)
    if options.use_special:
        pools.append(SPECIAL)
    if options.exclude_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    return [p for p in pools if p]


def generate_password(options: Optional[PasswordOptions] = None) -> str:
    """Генерирует криптографически стойкий пароль.

    В пароле гарантированно присутствует хотя бы один символ из каждого
    выбранного набора. Используется модуль ``secrets``.

    Raises:
        ValueError: если не выбран ни один набор символов или длина
            вне допустимого диапазона.
    """
    options = options or PasswordOptions()
    if not MIN_LENGTH <= options.length <= MAX_LENGTH:
        raise ValueError(
            f"Длина пароля должна быть от {MIN_LENGTH} до {MAX_LENGTH}.")
    pools = _active_pools(options)
    if not pools:
        raise ValueError("Выберите хотя бы один тип символов.")
    if options.length < len(pools):
        raise ValueError("Длина меньше количества выбранных типов символов.")

    # по одному символу из каждого набора + остальные из общего алфавита
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(options.length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Оценка сложности
# ---------------------------------------------------------------------------
@dataclass
class StrengthResult:
    """Результат оценки пароля."""

    score: int                      # 0..100
    level: str                      # текстовый уровень
    entropy: float                  # «сырая» энтропия, бит
    effective_entropy: float        # энтропия после штрафов, бит
    pool_size: int                  # размер алфавита
    hints: List[str] = field(default_factory=list)


def _is_common(password: str) -> bool:
    """Популярный пароль, в том числе с цифрами/символами в конце и заменой букв."""
    low = password.lower()
    base = low.rstrip(DIGITS + SPECIAL)
    return any(c in COMMON_PASSWORDS for c in (low, base, base.translate(_LEET)))


def _pool_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[а-яё]", password, re.I):
        size += 33
    if re.search(r"[^A-Za-z0-9а-яёА-ЯЁ]", password):
        size += len(SPECIAL) + 1  # спецсимволы + пробел
    return size


def _has_sequence(password: str, min_len: int = 3) -> bool:
    """Ищет последовательности вроде abc, 123, qwe (в обе стороны)."""
    low = password.lower()
    sources = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for src in sources:
        for variant in (src, src[::-1]):
            for i in range(len(variant) - min_len + 1):
                if variant[i:i + min_len] in low:
                    return True
    return False


def evaluate_password(password: str) -> StrengthResult:
    """Оценивает сложность пароля.

    Алгоритм:
        1. Базовая энтропия = длина * log2(размер алфавита).
        2. Штрафы за слабые шаблоны уменьшают эффективную энтропию:
           частый пароль, повторы символов, последовательности,
           малое число уникальных символов, только цифры/буквы.
        3. Эффективная энтропия переводится в оценку 0..100 и уровень.
    """
    if not password:
        return StrengthResult(0, LEVELS[0][1], 0.0, 0.0, 0,
                              ["Пароль пустой."])

    pool = _pool_size(password)
    entropy = len(password) * math.log2(pool) if pool > 1 else 0.0
    effective = entropy
    hints: List[str] = []

    if _is_common(password):
        effective = min(effective, 10)
        hints.append("Пароль входит в список самых популярных — не используйте его.")

    if re.search(r"(.)\1{2,}", password):
        effective *= 0.8
        hints.append("Есть повторы одного символа подряд (например, «aaa»).")

    if _has_sequence(password):
        effective *= 0.8
        hints.append("Есть последовательности (abc, 123, qwe) — их легко подобрать.")

    unique_ratio = len(set(password)) / len(password)
    if unique_ratio < 0.5:
        effective *= 0.8
        hints.append("Слишком много повторяющихся символов.")

    if password.isdigit():
        hints.append("Пароль состоит только из цифр.")
    elif password.isalpha():
        hints.append("Добавьте цифры и спецсимволы.")

    if len(password) < 12:
        hints.append("Рекомендуемая длина — не менее 12 символов.")
    if not re.search(r"[A-ZА-ЯЁ]", password) or not re.search(r"[a-zа-яё]", password):
        hints.append("Используйте и строчные, и заглавные буквы.")

    score = int(max(0, min(100, effective / 80 * 100)))
    level = next(name for limit, name in LEVELS if effective < limit)
    return StrengthResult(score, level, round(entropy, 1),
                          round(effective, 1), pool, hints)
