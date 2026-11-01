"""Генератор случайных паролей с оценкой сложности (Кейс 8).

Графический интерфейс на tkinter. Запуск:  python main.py

Структура проекта:
    main.py       — графический интерфейс и точка входа
    generator.py  — генерация паролей и оценка сложности
    database.py   — SQLite: пользователи и журнал их паролей (в зашифрованном виде)
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import List, Optional, Tuple

from database import Database, DatabaseError
from generator import (
    MAX_LENGTH, MIN_LENGTH, PasswordOptions, evaluate_password,
    generate_password,
)

STRENGTH_COLORS = ["#d32f2f", "#f57c00", "#fbc02d", "#7cb342", "#2e7d32"]


class FormDialog(tk.Toplevel):
    """Модальное окно с набором полей ввода. Результат — список значений или None."""

    def __init__(self, parent: tk.Misc, title: str,
                 fields: List[Tuple[str, bool]], text: str = ""):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        if parent.winfo_viewable():
            self.transient(parent)
        self.result: Optional[List[str]] = None

        if text:
            ttk.Label(self, text=text, wraplength=340, justify="left").grid(
                row=0, column=0, columnspan=2, padx=12, pady=(12, 4))
        self.entries = []
        for i, (label, secret) in enumerate(fields, start=1):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="w", padx=12, pady=4)
            entry = ttk.Entry(self, width=30, show="*" if secret else "")
            entry.grid(row=i, column=1, padx=12, pady=4)
            self.entries.append(entry)
        buttons = ttk.Frame(self)
        buttons.grid(row=len(fields) + 1, column=0, columnspan=2, pady=12)
        ttk.Button(buttons, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="left", padx=4)
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())

        self.entries[0].focus_set()
        self.wait_visibility()
        self.grab_set()           # модальность: остальные окна недоступны
        self.wait_window(self)

    def _ok(self) -> None:
        self.result = [e.get() for e in self.entries]
        self.destroy()


def ask_form(parent: tk.Misc, title: str, fields: List[Tuple[str, bool]],
             text: str = "") -> Optional[List[str]]:
    return FormDialog(parent, title, fields, text).result


def login(root: tk.Tk, db: Database) -> bool:
    """Запрашивает имя пользователя и ключ. False — пользователь отказался от входа."""
    while True:
        values = ask_form(
            root, "Вход",
            [("Пользователь:", False), ("Ключ:", True)],
            text="Введите имя пользователя и ключ. Если такого пользователя ещё "
                 "нет — он будет создан. Ключ нужен для доступа к вашему журналу "
                 "паролей, восстановить его нельзя.")
        if values is None:
            return False
        try:
            created = db.login(values[0], values[1])
        except DatabaseError as exc:
            messagebox.showerror("Ошибка", str(exc))
            continue
        if created:
            messagebox.showinfo("Готово", f"Создан новый пользователь «{db.username}».")
        return True


class App(ttk.Frame):
    """Главное окно приложения."""

    def __init__(self, root: tk.Tk, db: Database):
        super().__init__(root, padding=12)
        self.root = root
        self.db = db
        root.title(f"Генератор паролей — {db.username}")
        root.resizable(False, False)
        self.pack(fill="both", expand=True)

        self.length_var = tk.IntVar(value=16)
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        self.ambig_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=True)
        self._build_ui()

    # -- построение интерфейса ------------------------------------------
    def _build_ui(self) -> None:
        opts = ttk.LabelFrame(self, text="Параметры", padding=10)
        opts.grid(row=0, column=0, sticky="ew")

        ttk.Label(opts, text="Длина:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=MIN_LENGTH, to=MAX_LENGTH, width=5,
                    textvariable=self.length_var).grid(row=0, column=1, sticky="w")
        ttk.Scale(opts, from_=MIN_LENGTH, to=64, orient="horizontal", length=220,
                  command=lambda v: self.length_var.set(int(float(v)))
                  ).grid(row=0, column=2, padx=8)

        checks = [("Строчные буквы (a-z)", self.lower_var),
                  ("Заглавные буквы (A-Z)", self.upper_var),
                  ("Цифры (0-9)", self.digits_var),
                  ("Спецсимволы (!@#...)", self.special_var),
                  ("Исключить похожие символы (Il1O0o)", self.ambig_var)]
        for i, (text, var) in enumerate(checks, start=1):
            ttk.Checkbutton(opts, text=text, variable=var).grid(
                row=i, column=0, columnspan=3, sticky="w")

        ttk.Button(self, text="Сгенерировать пароль", command=self.on_generate
                   ).grid(row=1, column=0, sticky="ew", pady=8)

        pw_frame = ttk.LabelFrame(self, text="Пароль (можно ввести свой для проверки)",
                                  padding=10)
        pw_frame.grid(row=2, column=0, sticky="ew")
        self.entry = ttk.Entry(pw_frame, textvariable=self.password_var,
                               width=42, font=("Consolas", 12))
        self.entry.grid(row=0, column=0, columnspan=3, sticky="ew")
        self.entry.bind("<KeyRelease>", lambda e: self.update_strength())
        ttk.Checkbutton(pw_frame, text="Показывать", variable=self.show_var,
                        command=self.toggle_show).grid(row=1, column=0, sticky="w")
        ttk.Button(pw_frame, text="Копировать", command=self.on_copy
                   ).grid(row=1, column=1, padx=4)
        ttk.Button(pw_frame, text="Сохранить в журнал", command=self.on_save
                   ).grid(row=1, column=2)

        res = ttk.LabelFrame(self, text="Оценка сложности", padding=10)
        res.grid(row=3, column=0, sticky="ew", pady=8)
        self.bar = tk.Canvas(res, width=380, height=18, bg="#e0e0e0",
                             highlightthickness=0)
        self.bar.grid(row=0, column=0, sticky="w")
        self.bar_rect = self.bar.create_rectangle(0, 0, 0, 18, width=0, fill="#d32f2f")
        self.level_label = ttk.Label(res, text="—", font=("TkDefaultFont", 11, "bold"))
        self.level_label.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.info_label = ttk.Label(res, text="")
        self.info_label.grid(row=2, column=0, sticky="w")
        self.hints_label = ttk.Label(res, text="", wraplength=380, justify="left",
                                     foreground="#555")
        self.hints_label.grid(row=3, column=0, sticky="w", pady=(4, 0))

        ttk.Button(self, text="Открыть журнал паролей", command=self.open_journal
                   ).grid(row=4, column=0, sticky="ew")

    # -- обработчики ----------------------------------------------------
    def toggle_show(self) -> None:
        self.entry.config(show="" if self.show_var.get() else "•")

    def on_generate(self) -> None:
        try:
            options = PasswordOptions(
                length=int(self.length_var.get()),
                use_lower=self.lower_var.get(), use_upper=self.upper_var.get(),
                use_digits=self.digits_var.get(), use_special=self.special_var.get(),
                exclude_ambiguous=self.ambig_var.get())
            self.password_var.set(generate_password(options))
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Ошибка", str(exc) or "Некорректная длина пароля.")
            return
        self.update_strength()

    def update_strength(self) -> None:
        result = evaluate_password(self.password_var.get())
        color = STRENGTH_COLORS[min(len(STRENGTH_COLORS) - 1, result.score // 20)]
        self.bar.coords(self.bar_rect, 0, 0, 380 * result.score / 100, 18)
        self.bar.itemconfig(self.bar_rect, fill=color)
        self.level_label.config(text=f"{result.level} ({result.score}/100)",
                                foreground=color)
        self.info_label.config(
            text=f"Энтропия: {result.entropy} бит, с учётом штрафов: "
                 f"{result.effective_entropy} бит")
        self.hints_label.config(text="\n".join("• " + h for h in result.hints))

    def on_copy(self) -> None:
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Копирование", "Сначала сгенерируйте пароль.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        messagebox.showinfo("Копирование", "Пароль скопирован в буфер обмена.")

    def on_save(self) -> None:
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Сохранение", "Нечего сохранять.")
            return
        resource = simpledialog.askstring(
            "Ресурс", "Для какого ресурса (сайт, сервис) этот пароль?",
            parent=self.root)
        if not resource or not resource.strip():
            return
        resource = resource.strip()
        try:
            if self.db.resource_exists(resource):
                if not messagebox.askyesno(
                        "Ресурс уже есть",
                        f"Для ресурса «{resource}» пароль уже сохранён.\n"
                        "Обновить пароль?"):
                    return
            updated = self.db.save_password(resource, pw)
        except DatabaseError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        messagebox.showinfo(
            "Готово", f"Пароль для «{resource}» " + ("обновлён." if updated else "сохранён."))

    def open_journal(self) -> None:
        try:
            entries = self.db.get_journal()
        except DatabaseError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        JournalWindow(self.root, self.db, entries)


class JournalWindow(tk.Toplevel):
    """Модальное окно журнала паролей текущего пользователя."""

    def __init__(self, root: tk.Tk, db: Database,
                 entries: List[Tuple[str, str, str]]):
        super().__init__(root)
        self.title(f"Журнал паролей — {db.username}")
        self.transient(root)
        self.db = db
        self.entries = {res: (pw, date) for res, pw, date in entries}

        self.tree = ttk.Treeview(self, columns=("resource", "password", "date"),
                                 show="headings", height=10)
        self.tree.heading("resource", text="Ресурс")
        self.tree.heading("password", text="Пароль")
        self.tree.heading("date", text="Изменён")
        self.tree.column("date", width=130)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ttk.Frame(self)
        btns.pack(pady=(0, 8))
        self.reveal = tk.BooleanVar(value=False)
        ttk.Checkbutton(btns, text="Показать пароли", variable=self.reveal,
                        command=self.refresh).pack(side="left", padx=4)
        ttk.Button(btns, text="Копировать", command=self.copy_selected
                   ).pack(side="left", padx=4)
        ttk.Button(btns, text="Удалить", command=self.delete_selected
                   ).pack(side="left", padx=4)
        ttk.Button(btns, text="Закрыть", command=self.destroy
                   ).pack(side="left", padx=4)
        self.bind("<Escape>", lambda e: self.destroy())
        self.refresh()

        self.wait_visibility()
        self.grab_set()           # модальное окно: главное окно недоступно
        self.wait_window(self)

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for res, (pw, date) in sorted(self.entries.items()):
            self.tree.insert("", "end", iid=res, values=(
                res, pw if self.reveal.get() else "••••••••", date))

    def _selected(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    def copy_selected(self) -> None:
        res = self._selected()
        if res:
            self.clipboard_clear()
            self.clipboard_append(self.entries[res][0])

    def delete_selected(self) -> None:
        res = self._selected()
        if not res or not messagebox.askyesno(
                "Удаление", f"Удалить запись «{res}»?", parent=self):
            return
        try:
            self.db.delete_password(res)
        except DatabaseError as exc:
            messagebox.showerror("Ошибка", str(exc), parent=self)
            return
        del self.entries[res]
        self.refresh()


def main() -> None:
    root = tk.Tk()
    root.withdraw()                       # пока не вошли — главное окно скрыто
    db = Database()
    if not login(root, db):
        db.close()
        root.destroy()
        return
    root.deiconify()
    App(root, db)
    root.mainloop()
    db.close()


if __name__ == "__main__":
    main()
