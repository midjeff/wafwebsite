"""Synthetic fixtures and persistent SQLite storage."""
import sqlite3
from pathlib import Path

from flask import current_app, g
from werkzeug.security import generate_password_hash


def connect(path):
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize(path, reset=False):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        if reset:
            db.executescript("""
                DROP TABLE IF EXISTS login_attempts;
                DROP TABLE IF EXISTS comments;
                DROP TABLE IF EXISTS participants;
                DROP TABLE IF EXISTS tickets;
                DROP TABLE IF EXISTS users;
            """)
        db.executescript("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                scope TEXT NOT NULL, key TEXT NOT NULL, failures INTEGER NOT NULL,
                window_start REAL NOT NULL, blocked_until REAL NOT NULL,
                PRIMARY KEY (scope, key)
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, name TEXT NOT NULL,
                role TEXT NOT NULL, email TEXT NOT NULL, initials TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL, body TEXT NOT NULL,
                category TEXT NOT NULL, priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Открыта',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS participants (
                ticket_id INTEGER REFERENCES tickets(id),
                user_id INTEGER REFERENCES users(id),
                PRIMARY KEY(ticket_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL REFERENCES tickets(id),
                author_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Migrate only untouched fixture text; preserve user-edited tickets.
        db.execute("UPDATE tickets SET body = ? WHERE id = ? AND body = ?", ('Нужен адаптер для рабочего места в дизайн-команде.', 1001, 'Нужен адаптер для рабочего места в дизайн-команде. ALICE_PRIVATE'))
        db.execute("UPDATE tickets SET body = ? WHERE id = ? AND body = ?", ('Нужен доступ к финансовому разделу для подготовки квартального отчёта.', 1002, 'Тестовая заявка Бориса. BOB_PRIVATE — только искусственные данные.'))
        db.execute("UPDATE tickets SET body = ? WHERE id = ? AND body = ?", ('Проверим звук и видеосвязь в общей переговорной перед встречей.', 1003, 'Совместная заявка Алисы и Бориса. SHARED_TICKET'))
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        users = [
            (1, "alice", "Alice-Lab-2026!", "Алиса Морозова", "Дизайнер продукта", "alice@example.test", "АМ"),
            (2, "bob", "Bob-Lab-2026!", "Борис Волков", "Финансовый аналитик", "bob@example.test", "БВ"),
            (3, "it", "IT-Lab-2026!", "Марк Соколов", "Инженер поддержки", "mark@example.test", "МС"),
            (4, "elena", "Elena-Lab-2026!", "Елена Ким", "HR-партнёр", "elena@example.test", "ЕК"),
        ]
        db.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", [
            (uid, login, generate_password_hash(password), name, role, email, initials)
            for uid, login, password, name, role, email, initials in users
        ])
        db.executemany("INSERT INTO tickets (id, owner_id, title, body, category, priority, status) VALUES (?, ?, ?, ?, ?, ?, ?)", [
            (1001, 1, "Подключить второй монитор", "Нужен адаптер для рабочего места в дизайн-команде.", "Оборудование", "Обычный", "В работе"),
            (1002, 2, "Доступ к финансовому стенду", "Нужен доступ к финансовому разделу для подготовки квартального отчёта.", "Доступы", "Высокий", "Открыта"),
            (1003, 1, "Общая переговорная: проверка связи", "Проверим звук и видеосвязь в общей переговорной перед встречей.", "Сеть", "Обычный", "В работе"),
            (1004, 1, "Установка редактора макетов", "Приложение установлено, лицензия учебная.", "Программы", "Низкий", "Решена"),
        ])
        db.executemany("INSERT INTO participants VALUES (?, ?)", [(1003, 1), (1003, 2)])
        db.executemany("INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)", [
            (1001, 3, "Адаптер подготовлен. Доставим сегодня до 16:00."),
            (1003, 1, "Коллеги, проверьте звук перед встречей."),
            (1003, 2, "Подключение работает, спасибо!"),
        ])
