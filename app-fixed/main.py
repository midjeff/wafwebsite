"""Remediated implementation: fixes causes rather than demonstration payloads."""
import ipaddress
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

import click
from flask import Flask, abort, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash

from .db import close_db, get_db, initialize
from .process import bounded_run, ping_arguments

ROOT = Path(__file__).resolve().parent
DOCUMENTS = {"onboarding.txt": "Первый день в компании", "vpn.txt": "Подключение к учебной сети", "meetings.txt": "Переговорные и видеосвязь"}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def create_app(config=None):
    app = Flask(__name__)
    data_dir = Path(os.environ.get("DATA_DIR", ROOT.parent / ".runtime" / "fixed"))
    app.config.update(DATABASE=str(data_dir / "portal.db"), MAX_CONTENT_LENGTH=65536,
                      SESSION_COOKIE_NAME="nexus_fixed", SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False,
                      VERSION_LABEL="Исправленная версия", VERSION_STYLE="fixed")
    if config:
        app.config.update(config)
    initialize(app.config["DATABASE"])
    if not app.config.get("SECRET_KEY"):
        key_file = Path(app.config["DATABASE"]).parent / "session.key"
        if not key_file.exists():
            key_file.write_bytes(secrets.token_bytes(32))
        app.config["SECRET_KEY"] = key_file.read_bytes()
    app.teardown_appcontext(close_db)

    @app.before_request
    def load_user_and_csrf():
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (session.get("uid"),)).fetchone()
        if request.method == "POST":
            expected = session.get("csrf", "")
            provided = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, provided):
                abort(400, "Форма устарела. Обновите страницу и повторите действие.")

    @app.context_processor
    def template_context():
        def csrf_token():
            if "csrf" not in session:
                session["csrf"] = secrets.token_hex(24)
            return session["csrf"]
        return dict(csrf_token=csrf_token, documents=DOCUMENTS)

    @app.after_request
    def response_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.get("/health")
    def health():
        get_db().execute("SELECT 1").fetchone()
        return {"status": "ok", "version": "fixed"}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form.get("username", ""),)).fetchone()
            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                session.clear()
                session["uid"] = user["id"]
                session["csrf"] = secrets.token_hex(24)
                return redirect(url_for("dashboard"))
            error = "Неверный логин или пароль"
        return render_template("login.html", title="Вход в портал", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    def visible_tickets():
        return get_db().execute("""SELECT DISTINCT t.* FROM tickets t
            LEFT JOIN participants p ON p.ticket_id = t.id
            WHERE t.owner_id = ? OR p.user_id = ? ORDER BY t.id DESC""",
            (g.user["id"], g.user["id"])).fetchall()

    @app.get("/")
    @login_required
    def dashboard():
        tickets = visible_tickets()
        return render_template("dashboard.html", title="Обзор", tickets=tickets,
                               opened=sum(t["status"] != "Решена" for t in tickets))

    @app.get("/tickets")
    @login_required
    def tickets():
        return render_template("tickets.html", title="Мои заявки", tickets=visible_tickets())

    @app.route("/tickets/new", methods=["GET", "POST"])
    @login_required
    def new_ticket():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            category = request.form.get("category", "")
            priority = request.form.get("priority", "")
            if not title or len(title) > 150 or not body or len(body) > 4000:
                abort(400, "Укажите тему до 150 символов и описание до 4000 символов.")
            if category not in ("Оборудование", "Программы", "Доступы", "Сеть") or priority not in ("Низкий", "Обычный", "Высокий"):
                abort(400, "Выберите категорию и приоритет из списка.")
            db = get_db()
            result = db.execute("INSERT INTO tickets (owner_id, title, body, category, priority) VALUES (?, ?, ?, ?, ?)",
                                (g.user["id"], title, body, category, priority))
            db.commit()
            return redirect(url_for("ticket", ticket_id=result.lastrowid))
        return render_template("new_ticket.html", title="Новая заявка")

    def load_ticket(ticket_id):
        item = get_db().execute("SELECT t.*, u.name AS owner FROM tickets t JOIN users u ON u.id = t.owner_id WHERE t.id = ?", (ticket_id,)).fetchone()
        if item is None:
            abort(404)
        participant = get_db().execute("SELECT 1 FROM participants WHERE ticket_id = ? AND user_id = ?",
                                       (ticket_id, g.user["id"])).fetchone()
        if item["owner_id"] != g.user["id"] and participant is None:
            abort(403, "Эта заявка доступна только автору и её участникам.")
        return item

    @app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
    @login_required
    def ticket(ticket_id):
        item = load_ticket(ticket_id)
        db = get_db()
        if request.method == "POST":
            body = request.form.get("body", "").strip()
            if not body or len(body) > 4000:
                abort(400, "Комментарий должен содержать от 1 до 4000 символов.")
            db.execute("INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)", (ticket_id, g.user["id"], body))
            db.commit()
            return redirect(url_for("ticket", ticket_id=ticket_id))
        comments = db.execute("SELECT c.*, u.name, u.initials FROM comments c JOIN users u ON u.id = c.author_id WHERE c.ticket_id = ? ORDER BY c.id", (ticket_id,)).fetchall()
        return render_template("ticket.html", title=f"Заявка #{ticket_id}", ticket=item, comments=comments)

    @app.get("/employees")
    @login_required
    def employees():
        query = request.args.get("q", "")[:300]
        sql = "SELECT id, name, role, email, initials FROM users WHERE name LIKE ? ORDER BY id"
        try:
            people = get_db().execute(sql, (f"%{query}%",)).fetchall()
        except sqlite3.Error:
            return render_template("employees.html", title="Сотрудники", people=[], query=query, error="Ошибка SQL-запроса: изменена структура выражения."), 400
        return render_template("employees.html", title="Сотрудники", people=people, query=query)

    @app.get("/greeting")
    @login_required
    def greeting():
        return render_template("greeting.html", title="Приветствие", name=request.args.get("name", g.user["name"])[:500])

    @app.get("/documents")
    @login_required
    def documents():
        return render_template("documents.html", title="База знаний")

    @app.get("/download")
    @login_required
    def download():
        directory = (ROOT / "documents").resolve()
        try:
            target = (directory / request.args.get("file", "onboarding.txt")).resolve()
            target.relative_to(directory)
        except (ValueError, OSError, RuntimeError):
            abort(400, "Документ должен находиться внутри разрешённой папки.")
        if not target.is_file():
            abort(404)
        return send_file(target, mimetype="text/plain", as_attachment=request.args.get("attachment") == "1")

    @app.route("/diagnostics", methods=["GET", "POST"])
    @login_required
    def diagnostics():
        output = None
        host = request.form.get("host", "127.0.0.1")[:200]
        if request.method == "POST":
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                abort(400, "Введите корректный IP-адрес.")
            if not address.is_loopback:
                abort(400, "Учебная диагностика разрешает только loopback-адреса.")
            output = bounded_run(ping_arguments() + [str(address)], shell=False)
        return render_template("diagnostics.html", title="Диагностика сети", host=host, output=output)

    @app.get("/lab")
    def lab():
        return render_template("lab.html", title="Лабораторная работа")

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def error_page(error):
        return render_template("error.html", title=f"Ошибка {error.code}", error=error), error.code

    @app.cli.command("reset-db")
    def reset_db():
        """Reset only this application's synthetic SQLite data."""
        initialize(app.config["DATABASE"], reset=True)
        click.echo("PASS: учебная база восстановлена")

    @app.cli.command("clean-comments")
    def clean_comments():
        """Restore shared ticket comments before a stored-XSS demonstration."""
        db = get_db()
        db.execute("DELETE FROM comments WHERE ticket_id = 1003")
        db.executemany("INSERT INTO comments (ticket_id, author_id, body) VALUES (1003, ?, ?)",
                       [(1, "Коллеги, проверьте звук перед встречей."), (2, "Подключение работает, спасибо!")])
        db.commit()
        click.echo("PASS: комментарии общей заявки очищены")

    return app
