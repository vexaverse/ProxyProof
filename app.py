from flask import Flask, request, redirect, url_for, session, render_template_string, flash, make_response
import sqlite3, os, secrets, hashlib, csv, io, time
from functools import wraps
from datetime import datetime, timezone

APP_SECRET = os.environ.get("PROXYPROOF_SECRET", "change-this-secret-before-deployment")
DB_PATH = os.environ.get("PROXYPROOF_DB", "proxyproof.db")
TOKEN_ROTATION_SECONDS = 5
SESSION_DURATION_SECONDS = 5 * 60
RSSI_THRESHOLD = -75

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('organiser','student')),
            device_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attendance_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            organiser_id INTEGER NOT NULL REFERENCES users(id),
            started_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
            student_id INTEGER NOT NULL REFERENCES users(id),
            marked_at TEXT NOT NULL,
            UNIQUE(session_id, student_id)
        );
        CREATE TABLE IF NOT EXISTS used_device_marks (
            session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
            device_id TEXT NOT NULL,
            student_id INTEGER NOT NULL REFERENCES users(id),
            PRIMARY KEY(session_id, device_id)
        );
        """)
        # Demo accounts. Change passwords before using outside a local demo.
        seed_user(c, "organiser", "organiser123", "organiser")
        seed_user(c, "student1", "student123", "student")
        seed_user(c, "student2", "student123", "student")


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = hash_password(password, salt).split("$", 1)[1]
        return secrets.compare_digest(actual, expected)
    except ValueError:
        return False


def seed_user(c, username, password, role):
    exists = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not exists:
        c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                  (username, hash_password(password), role, datetime.now(timezone.utc).isoformat()))


def current_user():
    if "user_id" not in session:
        return None
    with db() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] != role:
                flash("You do not have permission to open that page.", "error")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def active_session(c):
    now = int(time.time())
    row = c.execute("""SELECT * FROM attendance_sessions
                       WHERE active=1 AND expires_at>? ORDER BY id DESC LIMIT 1""", (now,)).fetchone()
    return row


def token_for(session_id, started_at, expires_at, tick):
    # Deterministic short-lived token; the server validates the current time slice.
    secret = app.secret_key.encode()
    payload = f"{session_id}:{started_at}:{expires_at}:{tick}".encode()
    return hashlib.sha256(secret + b":" + payload).hexdigest()[:10].upper()


def valid_token(sess, submitted):
    now = int(time.time())
    if not sess or not sess["active"] or now >= sess["expires_at"]:
        return False
    tick = now // TOKEN_ROTATION_SECONDS
    # Small clock-boundary tolerance: current and immediately previous time slice.
    return any(secrets.compare_digest(token_for(sess["id"], sess["started_at"], sess["expires_at"], t),
                                      (submitted or "").strip().upper())
               for t in (tick, tick - 1))


STYLE = """
<style>
:root{--ink:#17243b;--muted:#68748b;--paper:#f6f7fb;--card:#fff;--accent:#6658d3;--line:#e5e8f1;--green:#16845b;--red:#b42318}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif}
nav{background:#151e33;color:white;padding:16px max(22px,calc((100% - 1100px)/2));display:flex;justify-content:space-between;gap:16px;align-items:center}
nav a{color:white;text-decoration:none;margin-left:15px}.brand{font-weight:850;letter-spacing:-.5px}
main{max-width:1100px;margin:32px auto;padding:0 20px}.hero{padding:26px 0 12px}.eyebrow{color:var(--accent);font-weight:800;text-transform:uppercase;font-size:12px;letter-spacing:1.6px}
h1{font-size:clamp(28px,4vw,42px);line-height:1.1;margin:8px 0}h2{font-size:21px;margin-top:0}p{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 5px 20px #1d2a4b08;margin-bottom:18px}
.stat{font-size:32px;font-weight:850;letter-spacing:-1px}.muted{color:var(--muted)}label{display:block;font-weight:700;margin:12px 0 5px}
input,select{width:100%;padding:12px 13px;border:1px solid #d7dbea;border-radius:9px;font:inherit;background:white}
button,.btn{display:inline-block;border:0;border-radius:9px;padding:11px 16px;background:var(--accent);color:white;font-weight:750;font:inherit;text-decoration:none;cursor:pointer;margin-top:12px}
button.secondary,.btn.secondary{background:#e9e7fb;color:#3f368e}button.danger{background:#b42318}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid var(--line)}th{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted)}
.badge{display:inline-block;padding:4px 9px;border-radius:99px;background:#e5f7ef;color:var(--green);font-size:12px;font-weight:800}.badge.off{background:#fff0ed;color:var(--red)}
.flash{padding:12px 14px;background:#fff4d8;border-radius:9px;margin:12px 0}.flash.error{background:#ffe9e7}
.token{font-size:30px;letter-spacing:5px;font-weight:900;color:var(--accent);padding:12px;background:#f0efff;border-radius:10px;text-align:center}
.small{font-size:13px}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.row form{margin:0}
footer{color:var(--muted);text-align:center;padding:28px;font-size:12px}
@media(max-width:600px){nav{align-items:flex-start;flex-direction:column}nav a{margin:0 12px 0 0}main{margin-top:18px}table{font-size:13px}}
</style>
"""

SHELL = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · ProxyProof</title>""" + STYLE + """</head><body>
<nav><a class="brand" href="{{ url_for('index') }}">◉ ProxyProof</a><div>
{% if user %}<span class="small">{{ user['username'] }} · {{ user['role'] }}</span><a href="{{ url_for('index') }}">Dashboard</a><a href="{{ url_for('logout') }}">Log out</a>
{% else %}<a href="{{ url_for('login') }}">Log in</a>{% endif %}</div></nav>
<main>{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<div class="flash {{ category }}">{{ message }}</div>{% endfor %}{% endwith %}
{{ body|safe }}</main><footer>ProxyProof · BLE-inspired attendance demo · Built for learning</footer></body></html>
"""


def page(title, body, **context):
    return render_template_string(SHELL, title=title, body=render_template_string(body, **context),
                                  user=current_user())


@app.route("/")
def index():
    user = current_user()
    if not user:
        body = """
        <section class="hero"><div class="eyebrow">Secure attendance, simplified</div><h1>Presence you can verify.</h1>
        <p>ProxyProof demonstrates short-lived attendance tokens, device binding and a live organiser dashboard.</p></section>
        <div class="grid"><div class="card"><h2>🛡️ Anti-proxy checks</h2><p>Fresh rotating tokens, one registered device per student, and one student per device per session.</p></div>
        <div class="card"><h2>📊 Attendance analytics</h2><p>View attendance history, calculate percentages and export a CSV report.</p></div></div>
        <div class="card"><h2>Try the demo</h2><p><b>Organiser:</b> organiser / organiser123<br><b>Student:</b> student1 / student123<br><b>Second student:</b> student2 / student123</p><a class="btn" href="{{ url_for('login') }}">Sign in</a></div>"""
        return page("Home", body)
    if user["role"] == "organiser":
        return redirect(url_for("organiser_dashboard"))
    return redirect(url_for("student_dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = False
            return redirect(url_for("index"))
        flash("Incorrect username or password.", "error")
    body = """
    <section class="hero"><div class="eyebrow">Welcome back</div><h1>Sign in to ProxyProof</h1><p>Use one of the local demo accounts shown on the home page.</p></section>
    <div class="card" style="max-width:500px"><form method="post"><label>Username</label><input name="username" required autocomplete="username">
    <label>Password</label><input name="password" type="password" required autocomplete="current-password"><button type="submit">Sign in</button></form></div>"""
    return page("Login", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/organiser")
@login_required("organiser")
def organiser_dashboard():
    with db() as c:
        sess = active_session(c)
        recent = c.execute("""SELECT s.*,u.username FROM attendance_sessions s JOIN users u ON u.id=s.organiser_id
                              ORDER BY s.id DESC LIMIT 10""").fetchall()
        students = c.execute("""SELECT u.id,u.username,COUNT(a.id) AS attended
                                FROM users u LEFT JOIN attendance a ON a.student_id=u.id
                                WHERE u.role='student' GROUP BY u.id ORDER BY u.username""").fetchall()
        marks = []
        if sess:
            marks = c.execute("""SELECT u.username,a.marked_at FROM attendance a JOIN users u ON u.id=a.student_id
                                 WHERE a.session_id=? ORDER BY a.marked_at DESC""", (sess["id"],)).fetchall()
    now = int(time.time())
    token = token_for(sess["id"], sess["started_at"], sess["expires_at"], now // TOKEN_ROTATION_SECONDS) if sess else None
    body = """
    <section class="hero"><div class="eyebrow">Organiser workspace</div><h1>Attendance dashboard</h1>
    <p>Start a time-limited session, monitor marks and export attendance.</p></section>
    <div class="grid"><div class="card"><div class="muted">Registered students</div><div class="stat">{{ students|length }}</div></div>
    <div class="card"><div class="muted">Current session</div><div class="stat">{{ 'Live' if sess else 'None' }}</div><p>{% if sess %}{{ sess['title'] }}{% else %}Start a session below.{% endif %}</p></div></div>
    <div class="card"><h2>Session controls</h2>
    {% if sess %}<span class="badge">SESSION ACTIVE</span><p>Expires in about {{ [sess['expires_at']-now,0]|max }} seconds.</p><div class="token">{{ token }}</div>
    <p class="small">Demo token rotates every {{ rotation }} seconds. In production, broadcast it over BLE from the organiser device.</p>
    <div class="row"><a class="btn secondary" href="{{ url_for('organiser_dashboard') }}">Refresh token</a><form method="post" action="{{ url_for('close_session',session_id=sess['id']) }}"><button class="danger">Close session</button></form></div>
    {% else %}<form method="post" action="{{ url_for('start_session') }}"><label>Session name</label><input name="title" placeholder="e.g. Tech Club Meeting" required maxlength="80"><label>Duration (minutes)</label><select name="duration"><option value="5">5 minutes</option><option value="10">10 minutes</option><option value="30">30 minutes</option></select><button>Start attendance session</button></form>{% endif %}</div>
    <div class="card"><h2>Live attendance {% if sess %}<span class="badge">{{ marks|length }} present</span>{% endif %}</h2>
    {% if sess %}<table><thead><tr><th>Student</th><th>Marked at</th><th>Action</th></tr></thead><tbody>
    {% for m in marks %}<tr><td>{{ m['username'] }}</td><td>{{ m['marked_at'] }}</td><td><form method="post" action="{{ url_for('remove_mark',session_id=sess['id'],username=m['username']) }}"><button class="secondary">Remove</button></form></td></tr>{% else %}<tr><td colspan="3">No attendance marks yet.</td></tr>{% endfor %}</tbody></table>
    <div class="row"><form method="post" action="{{ url_for('manual_mark',session_id=sess['id']) }}"><label>Manual add student</label><select name="student_id">{% for s in students %}<option value="{{ s['id'] }}">{{ s['username'] }}</option>{% endfor %}</select><button class="secondary">Add manually</button></form></div>
    {% else %}<p class="muted">Start a session to see live marks here.</p>{% endif %}</div>
    <div class="card"><h2>Student attendance summary</h2><table><thead><tr><th>Student</th><th>Marks</th><th>Attendance %</th><th>Device</th></tr></thead><tbody>
    {% for s in students %}<tr><td>{{ s['username'] }}</td><td>{{ s['attended'] }}</td><td>{{ ((s['attended']/total_sessions)*100)|round(1) if total_sessions else 0 }}%</td><td>{{ 'Bound' if device_map[s['id']] else 'Not bound' }}</td></tr>{% endfor %}</tbody></table>
    <p><a class="btn secondary" href="{{ url_for('export_csv') }}">Export all attendance CSV</a></p></div>
    <script>setTimeout(()=>location.reload(),5000)</script>"""
    with db() as c:
        total_sessions = c.execute("SELECT COUNT(*) FROM attendance_sessions WHERE active=0 OR expires_at<=?", (now,)).fetchone()[0]
        device_map = {r["id"]: r["device_id"] for r in c.execute("SELECT id,device_id FROM users WHERE role='student'")}
    return page("Organiser", body, sess=sess, students=students, marks=marks, token=token, now=now,
                rotation=TOKEN_ROTATION_SECONDS, total_sessions=total_sessions, device_map=device_map)


@app.route("/session/start", methods=["POST"])
@login_required("organiser")
def start_session():
    title = request.form.get("title", "").strip()[:80]
    try:
        duration = max(1, min(int(request.form.get("duration", "5")), 60))
    except ValueError:
        duration = 5
    if not title:
        flash("Enter a session name.", "error")
        return redirect(url_for("organiser_dashboard"))
    now = int(time.time())
    with db() as c:
        c.execute("UPDATE attendance_sessions SET active=0 WHERE active=1")
        c.execute("INSERT INTO attendance_sessions(title,organiser_id,started_at,expires_at,active) VALUES(?,?,?,?,1)",
                  (title, session["user_id"], now, now + duration*60))
    flash("Attendance session started.", "success")
    return redirect(url_for("organiser_dashboard"))


@app.route("/session/<int:session_id>/close", methods=["POST"])
@login_required("organiser")
def close_session(session_id):
    with db() as c:
        c.execute("UPDATE attendance_sessions SET active=0 WHERE id=?", (session_id,))
    flash("Session closed.", "success")
    return redirect(url_for("organiser_dashboard"))


@app.route("/student")
@login_required("student")
def student_dashboard():
    user = current_user()
    with db() as c:
        sess = active_session(c)
        history = c.execute("""SELECT s.title,a.marked_at FROM attendance a JOIN attendance_sessions s ON s.id=a.session_id
                               WHERE a.student_id=? ORDER BY a.marked_at DESC LIMIT 20""", (user["id"],)).fetchall()
        total = c.execute("SELECT COUNT(*) FROM attendance_sessions").fetchone()[0]
        attended = c.execute("SELECT COUNT(*) FROM attendance WHERE student_id=?", (user["id"],)).fetchone()[0]
    body = """
    <section class="hero"><div class="eyebrow">Student workspace</div><h1>Hello, {{ user['username'] }}</h1><p>Bind your browser/device once, then mark attendance during an active session.</p></section>
    <div class="grid"><div class="card"><div class="muted">Attendance rate</div><div class="stat">{{ ((attended/total)*100)|round(1) if total else 0 }}%</div><p>{{ attended }} of {{ total }} sessions marked</p></div>
    <div class="card"><div class="muted">Device status</div><div class="stat" style="font-size:25px">{{ 'Bound' if user['device_id'] else 'Not bound' }}</div><p class="small">A student account can bind to one device ID.</p></div></div>
    <div class="card"><h2>Device registration</h2><p>The browser creates a random device ID and stores it locally. This is a demo approximation; production mobile apps should use platform-backed device keys.</p>
    <button onclick="bindDevice()">Register this device</button><p id="device-status" class="small"></p></div>
    <div class="card"><h2>Current session</h2>{% if sess %}<span class="badge">ACTIVE</span><h3>{{ sess['title'] }}</h3><p>Session closes in about {{ [sess['expires_at']-now,0]|max }} seconds.</p>
    <form method="post" action="{{ url_for('mark_attendance',session_id=sess['id']) }}" onsubmit="return attachDevice()">
    <input type="hidden" name="device_id" id="device-id"><input type="hidden" name="rssi" value="-55"><label>Rotating token from organiser dashboard</label><input name="token" placeholder="Enter current 10-character token" required maxlength="10" style="text-transform:uppercase"><button>Mark attendance</button></form>
    <p class="small">For this web demo, token entry simulates receiving the BLE broadcast. Real proximity requires native BLE scanning and server-validated signed tokens.</p>
    {% else %}<p>No active attendance session right now. Check back when your organiser starts one.</p>{% endif %}</div>
    <div class="card"><h2>Attendance history</h2><table><thead><tr><th>Session</th><th>Marked at</th></tr></thead><tbody>{% for h in history %}<tr><td>{{ h['title'] }}</td><td>{{ h['marked_at'] }}</td></tr>{% else %}<tr><td colspan="2">No attendance history yet.</td></tr>{% endfor %}</tbody></table></div>
    <script>
    function getDevice(){let d=localStorage.getItem('proxyproof-device');if(!d){d='pp-'+crypto.randomUUID();localStorage.setItem('proxyproof-device',d)}return d}
    function bindDevice(){fetch('{{ url_for("bind_device") }}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_id:getDevice()})}).then(r=>r.json()).then(x=>{document.getElementById('device-status').textContent=x.message;setTimeout(()=>location.reload(),900)})}
    function attachDevice(){document.getElementById('device-id').value=getDevice();return true}
    </script><script>setTimeout(()=>location.reload(),10000)</script>"""
    return page("Student", body, user=user, sess=sess, history=history, total=total, attended=attended, now=int(time.time()))


@app.route("/student/bind-device", methods=["POST"])
@login_required("student")
def bind_device():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", ""))[:100]
    if not device_id.startswith("pp-"):
        return {"ok": False, "message": "Invalid device ID."}, 400
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        other = c.execute("SELECT username FROM users WHERE device_id=?", (device_id,)).fetchone()
        if user["device_id"] and user["device_id"] != device_id:
            return {"ok": False, "message": "This account is already bound. Ask the organiser to approve a device change."}, 409
        if other and other["username"] != user["username"]:
            return {"ok": False, "message": "This device is already bound to another student."}, 409
        c.execute("UPDATE users SET device_id=? WHERE id=?", (device_id, user["id"]))
    return {"ok": True, "message": "Device registered successfully."}


@app.route("/session/<int:session_id>/mark", methods=["POST"])
@login_required("student")
def mark_attendance(session_id):
    user = current_user()
    device_id = request.form.get("device_id", "")[:100]
    submitted_token = request.form.get("token", "")
    try:
        rssi = int(request.form.get("rssi", "-100"))
    except ValueError:
        rssi = -100
    with db() as c:
        sess = c.execute("SELECT * FROM attendance_sessions WHERE id=?", (session_id,)).fetchone()
        latest = active_session(c)
        if not sess or not latest or latest["id"] != session_id or not valid_token(sess, submitted_token):
            flash("Token invalid or expired. Use the current token from the organiser dashboard.", "error")
        elif not user["device_id"] or not secrets.compare_digest(user["device_id"], device_id):
            flash("This device is not registered to your account. Register it first.", "error")
        elif rssi < RSSI_THRESHOLD:
            flash("Signal appears too weak. Move closer to the organiser.", "error")
        elif c.execute("SELECT 1 FROM used_device_marks WHERE session_id=? AND device_id=?", (session_id, device_id)).fetchone():
            flash("This device has already been used to mark attendance in this session.", "error")
        else:
            try:
                c.execute("INSERT INTO attendance(session_id,student_id,marked_at) VALUES(?,?,?)",
                          (session_id, user["id"], datetime.now(timezone.utc).isoformat(timespec="seconds")))
                c.execute("INSERT INTO used_device_marks(session_id,device_id,student_id) VALUES(?,?,?)",
                          (session_id, device_id, user["id"]))
                flash("Attendance marked successfully!", "success")
            except sqlite3.IntegrityError:
                flash("Attendance has already been recorded for this session.", "error")
    return redirect(url_for("student_dashboard"))


@app.route("/session/<int:session_id>/manual-mark", methods=["POST"])
@login_required("organiser")
def manual_mark(session_id):
    student_id = request.form.get("student_id", type=int)
    with db() as c:
        sess = c.execute("SELECT * FROM attendance_sessions WHERE id=?", (session_id,)).fetchone()
        student = c.execute("SELECT id FROM users WHERE id=? AND role='student'", (student_id,)).fetchone()
        if not sess or not student:
            flash("Invalid session or student.", "error")
        else:
            try:
                c.execute("INSERT INTO attendance(session_id,student_id,marked_at) VALUES(?,?,?)",
                          (session_id, student_id, datetime.now(timezone.utc).isoformat(timespec="seconds")))
                flash("Manual attendance added.", "success")
            except sqlite3.IntegrityError:
                flash("That student is already marked present.", "error")
    return redirect(url_for("organiser_dashboard"))


@app.route("/session/<int:session_id>/remove/<username>", methods=["POST"])
@login_required("organiser")
def remove_mark(session_id, username):
    with db() as c:
        c.execute("""DELETE FROM attendance WHERE session_id=? AND student_id=(SELECT id FROM users WHERE username=?)""",
                  (session_id, username))
        c.execute("""DELETE FROM used_device_marks WHERE session_id=? AND student_id=(SELECT id FROM users WHERE username=?)""",
                  (session_id, username))
    flash(f"Attendance removed for {username}.", "success")
    return redirect(url_for("organiser_dashboard"))


@app.route("/export.csv")
@login_required("organiser")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["session_id", "session_title", "student_username", "marked_at"])
    with db() as c:
        rows = c.execute("""SELECT s.id,s.title,u.username,a.marked_at FROM attendance a
                            JOIN attendance_sessions s ON s.id=a.session_id JOIN users u ON u.id=a.student_id
                            ORDER BY s.id DESC,a.marked_at""").fetchall()
        for r in rows:
            writer.writerow([r["id"], r["title"], r["username"], r["marked_at"]])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=proxyproof-attendance.csv"
    return response


@app.route("/health")
def health():
    return {"status": "ok", "service": "ProxyProof"}


if __name__ == "__main__":
    init_db()
    print("ProxyProof is running at http://127.0.0.1:5000")
    print("Demo organiser: organiser / organiser123")
    print("Demo student: student1 / student123")
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
