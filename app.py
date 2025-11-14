import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

# --- Config ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = "taskmaster.sqlite3"
# --- DB Helpers ---
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

# --- Auth Decorator ---
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

# --- Routes: Auth ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("نام کاربری و رمز عبور لازم است.", "error")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
            flash("ثبت‌نام موفق! حالا وارد شوید.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("این نام کاربری قبلاً گرفته شده.", "error")
            return redirect(url_for("register"))
        except Exception as e:
            flash(f"خطا: {str(e)}", "error")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        flash("نام کاربری یا رمز عبور نادرست است.", "error")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Routes: Tasks ---
@app.route("/", methods=["GET"])
@login_required
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    if q:
        tasks = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ? ORDER BY created_at DESC",
            (session["user_id"], f"%{q}%"),
        ).fetchall()
    else:
        tasks = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()
    return render_template("index.html", tasks=tasks, q=q)

@app.route("/task", methods=["POST"])
@login_required
def add_task():
    title = request.form.get("title", "").strip()
    if not title:
        flash("عنوان تسک لازم است.", "error")
        return redirect(url_for("index"))
    db = get_db()
    db.execute(
        "INSERT INTO tasks (user_id, title) VALUES (?, ?)",
        (session["user_id"], title),
    )
    db.commit()
    return redirect(url_for("index"))

@app.route("/task/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    db = get_db()
    row = db.execute(
        "SELECT is_done FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"])
    ).fetchone()
    if row:
        new_val = 0 if row["is_done"] else 1
        db.execute(
            "UPDATE tasks SET is_done = ? WHERE id = ? AND user_id = ?",
            (new_val, task_id, session["user_id"])
        )
        db.commit()
    return redirect(url_for("index"))

@app.route("/task/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    db = get_db()
    db.execute(
        "DELETE FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"]),
    )
    db.commit()
    return redirect(url_for("index"))

if __name__ == "__main__":
    # ایجاد دیتابیس اگر وجود ندارد
    if not os.path.exists(DB_PATH):
        print("Creating database...")
        conn = sqlite3.connect(DB_PATH)
        with open('schema.sql', 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()
        print("Database created successfully!")

    app.run(debug=True, host="0.0.0.0", port=5000)
