from functools import wraps
from flask import(Blueprint, g, render_template,
                  request, session, url_for, flash, redirect)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='auth')


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs)


@bp.route("/register", methods=['GET', 'POST'])
def register():
    if method == 'POST':
        username, password = request.form['username'], request.form['password']
        db = get_db()

        if not username:
            error = "Username is required"
        elif not password:
            error = "Password is required"
        elif db.execute("SELECT id FROM user WHERE username= ?", (username,)).fetchone() is not None:
            error = f"Username {username} is already taken"

        if error is None:
            db.execute("INSERT INTO user (username, password) VALUES (?, ?)",
                       (username, generate_password_hash(password), ))
            db.commit()
        flash(error)
    return render_template("auth/register.html")


@bp.route("/login", methods=['GET', 'POST'])
def login:
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.execute("SELECT * FROM user WHERE username=?",
                          (username,)).fetchone()

        if user is None:
            error = "Username is incorrect"
        elif not check_password_hash(password, user['password']):
            error = "Password is incorrect"

        if error is None:
            session.clear()
            session['user_id'] = user["id"]
            return redirect(url_for('index'))
        flash(error)
        return render_template('login.html')


@bp.route('/logout')
def logout:
    session.clear()
    return redirect(url_for('index'))
