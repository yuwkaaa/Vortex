import io
import os
import time
import uuid
import sqlite3
import hashlib
import subprocess
import threading
import secrets

from PIL import Image

from mimeparse import parse_mime_type

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename
from playwright.sync_api import sync_playwright

# ── Config ────────────────────────────────────────────────────────────────────

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "sup3r_s3cr3t_4dm1n")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/photos")
DATABASE = os.environ.get("DATABASE", "/tmp/photo_storage.db")
APP_PORT = int(os.environ.get("APP_PORT", "3000"))
BOT_TIMEOUT = int(os.environ.get("BOT_TIMEOUT", "5000"))

ALLOWED_IMAGE_TYPES = ["png", "jpeg", "gif", "webp"]

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False

# ── Database helpers ──────────────────────────────────────────────────────────


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            content_type TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
    )
    db.commit()

    # Create admin user if not exists
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        pass

    db.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ── Auth helpers ──────────────────────────────────────────────────────────────


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user() is None:
            flash("Пожалуйста, войдите в систему.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("Пожалуйста, войдите в систему.", "warning")
            return redirect(url_for("login"))
        if user["username"] != ADMIN_USERNAME:
            flash("Доступ запрещён.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            flash("Введите имя пользователя и пароль.", "danger")
            return render_template("register.html")

        if username == ADMIN_USERNAME:
            flash("Это имя пользователя зарезервировано.", "danger")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Имя пользователя уже занято.", "danger")
            return render_template("register.html")

        flash("Регистрация прошла успешно! Войдите.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, hash_password(password)),
        ).fetchone()

        if user is None:
            flash("Неверное имя пользователя или пароль.", "danger")
            return render_template("login.html")

        session["user_id"] = user["id"]
        flash(f"Добро пожаловать, {username}!", "success")
        return redirect(url_for("gallery"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("photo")
        if file is None or file.filename == "":
            flash("Выберите файл для загрузки.", "danger")
            return render_template("upload.html", user=current_user())

        content_type = file.content_type or "text/plain"
        parts = parse_mime_type(content_type)
        if parts[0] != 'image' or parts[1] not in ALLOWED_IMAGE_TYPES:
            flash("Разрешены только изображения.", "danger")
            return render_template("upload.html", user=current_user())

        try:
            file_bytes: bytes = file.read()
            Image.open(io.BytesIO(bytes(file_bytes))).verify()
        except Exception:
            flash("Разрешены только изображения.", "danger")
            return render_template("upload.html", user=current_user())

        file_id = str(uuid.uuid4())
        original_name = secure_filename(file.filename or "unnamed")
        stored_path = os.path.join(UPLOAD_DIR, file_id)

        with open(stored_path, 'wb') as f:
            f.write(file_bytes)

        db = get_db()
        db.execute(
            "INSERT INTO files (id, user_id, original_name, content_type, stored_path) "
            "VALUES (?, ?, ?, ?, ?)",
            (file_id, session["user_id"], original_name, content_type, stored_path),
        )
        db.commit()

        flash("Файл загружен!", "success")
        return redirect(url_for("gallery"))

    return render_template("upload.html", user=current_user())


@app.route("/gallery")
@login_required
def gallery():
    db = get_db()
    files = db.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY rowid DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("gallery.html", user=current_user(), files=files)


@app.route("/file/<file_id>")
def public_file(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return "Файл не найден.", 404

    return send_file(
        row["stored_path"],
        mimetype=row["content_type"],
        download_name=row["original_name"],
    )

# ── Admin panel ───────────────────────────────────────────────────────────────


@app.route("/admin")
@admin_required
def admin_panel():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    db = get_db()
    files = db.execute(
        "SELECT files.*, users.username FROM files "
        "JOIN users ON files.user_id = users.id "
        "ORDER BY files.rowid DESC"
    ).fetchall()
    return render_template("admin.html", user=current_user(), files=files, csrf_token=session["csrf_token"])


@app.route("/admin/compress", methods=["POST"])
@admin_required
def admin_compress():
    csrf_token = (request.form.get("csrf_token") or "").strip()
    if not csrf_token or csrf_token != session.get("csrf_token"):
        flash("В доступе отказано: неверный CSRF-токен.", "danger")
        return redirect(url_for("admin_panel"))

    file_id = (request.form.get("file_id") or "").strip()
    quality = (request.form.get("quality") or "").strip()

    if not file_id or not quality:
        flash("Укажите файл и качество.", "danger")
        return redirect(url_for("admin_panel"))

    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        flash("Файл не найден.", "danger")
        return redirect(url_for("admin_panel"))

    input_path = row["stored_path"]
    output_path = input_path + "_compressed"

    cmd = f"convert {input_path} -quality {quality} {output_path}"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        if result.returncode == 0:
            flash(f"Сжатие завершено. {output}", "success")
        else:
            flash(f"Ошибка convert: {output}", "danger")
    except subprocess.TimeoutExpired:
        flash("Таймаут операции.", "danger")
    except Exception as e:
        flash(f"Ошибка: {e}", "danger")

    return redirect(url_for("admin_panel"))

# ── Bot / Report ──────────────────────────────────────────────────────────────


bot_lock = threading.Lock()
last_report: dict[str, float] = {}
REPORT_COOLDOWN = 60  # seconds


def _visit_url(url: str) -> str:
    with bot_lock:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = browser.new_context()
            page = ctx.new_page()

            # Bot logs in as admin first
            try:
                page.goto(
                    f"http://127.0.0.1:{APP_PORT}/login",
                    wait_until="networkidle",
                    timeout=BOT_TIMEOUT,
                )
                page.fill('input[name="username"]', ADMIN_USERNAME)
                page.fill('input[name="password"]', ADMIN_PASSWORD)
                page.click('button[type="submit"]')
                page.wait_for_load_state("networkidle", timeout=BOT_TIMEOUT)
            except Exception as err:
                print('bot cant login:', err)

            # Now visit the reported URL
            try:
                page.goto(url, wait_until="networkidle", timeout=BOT_TIMEOUT)
            except Exception:
                pass

            browser.close()
    return "OK"


@app.route("/report", methods=["GET", "POST"])
def report():
    result = None
    error = None

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        now = time.time()
        last = last_report.get(ip, 0)
        if now - last < REPORT_COOLDOWN:
            wait = int(REPORT_COOLDOWN - (now - last)) + 1
            error = f"Подождите {wait} сек. перед следующим запросом."
        else:
            url = (request.form.get("url") or "").strip()
            if not url:
                error = "Введите ссылку."
            elif not url.startswith("http://") and not url.startswith("https://"):
                error = "Ссылка должна начинаться с http:// или https://."
            else:
                try:
                    last_report[ip] = now
                    _visit_url(url)
                    result = "Бот посетил ссылку. Спасибо за обратную связь!"
                except Exception as e:
                    error = f"Ошибка: {e}"

    return render_template("report.html", user=current_user(), result=result, error=error)

# ── Main ──────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=APP_PORT, threaded=True)
