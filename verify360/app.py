# ================================================================
#  VERIFY360 — Python Flask Backend
#  SQLite database + Admin Panel + Scan API
# ================================================================

from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, flash)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, json, re
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "verify360-secret-key-change-in-production")
CORS(app, supports_credentials=True)

DB_PATH = os.path.join(os.path.dirname(__file__), "verify360.db")

# ================================================================
#  ⚙️  ADMIN CREDENTIALS — CHANGE THESE BEFORE SHARING THE PROJECT
#  Only the person with these credentials can access /admin
# ================================================================
ADMIN_USERNAME = "admin"          # ← change this to your username
ADMIN_PASSWORD = "verify360@2026" # ← change this to your password


# ================================================================
#  DATABASE
# ================================================================

def get_db():
    """Open a database connection (creates file if not exists)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create all tables on first run."""
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS known_scams (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            value       TEXT    NOT NULL,
            type        TEXT    NOT NULL CHECK(type IN ('Phone','WhatsApp','Website','Instagram')),
            description TEXT,
            source      TEXT,
            reports     INTEGER NOT NULL DEFAULT 1,
            added_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(value, type)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            input       TEXT    NOT NULL,
            type        TEXT    NOT NULL,
            risk_level  TEXT    NOT NULL,
            threat      INTEGER NOT NULL DEFAULT 0,
            score       INTEGER NOT NULL DEFAULT 0,
            reasons     TEXT,
            scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            input       TEXT    NOT NULL,
            type        TEXT    NOT NULL,
            description TEXT,
            reported_by TEXT,
            reported_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
    print("✅ Database initialised:", DB_PATH)


# ================================================================
#  ADMIN AUTH — decorator + login/logout
# ================================================================

def admin_required(f):
    """
    Decorator that protects any route so only the admin
    (verified by session flag 'is_admin') can access it.
    Anyone else gets a 403 page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            # Log the attempted access (silent — don't tell the user why)
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Separate login page exclusively for the admin."""
    # Already logged in as admin — go straight to panel
    if session.get("is_admin"):
        return redirect("/admin")

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.permanent = True
            session["is_admin"]       = True
            session["admin_username"] = username
            return redirect("/admin")
        else:
            # Generic error — don't reveal whether username or password was wrong
            error = "Invalid credentials. Access denied."

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    """Clear only the admin session flags."""
    session.pop("is_admin", None)
    session.pop("admin_username", None)
    return redirect("/admin/login")


# ================================================================
#  DETECTION ENGINE
# ================================================================

SCAM_KEYWORDS = [
    "lottery","lotto","winner","prize","jackpot","free money",
    "loan","urgent","offer","crypto","bitcoin","investment",
    "double your","click here","limited time","congratulations",
    "earn from home","work from home","guaranteed","otp",
    "bank account","kyc","reward","verify your",
]

def keyword_score(text):
    lower = text.lower()
    hits  = [k for k in SCAM_KEYWORDS if k in lower]
    return len(hits) * 15, hits

def levenshtein(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0] = i
    for j in range(n+1): dp[0][j] = j
    for i in range(1,m+1):
        for j in range(1,n+1):
            dp[i][j] = dp[i-1][j-1] if a[i-1]==b[j-1] \
                       else 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]

def is_known_scam(value, type_):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM known_scams WHERE LOWER(value)=? AND type=?",
            (value.lower(), type_)
        ).fetchone()
    return dict(row) if row else None

def build_result(score, reasons):
    score = min(score, 100)
    if   score >= 60: risk, threat = "HIGH",   True
    elif score >= 30: risk, threat = "MEDIUM",  True
    else:             risk, threat = "LOW",    False
    return {"score": score, "risk_level": risk, "threat": threat, "reasons": reasons}


# ── Phone ─────────────────────────────────────────────────────────
def detect_phone(inp):
    reasons, score = [], 0
    digits = re.sub(r'\D', '', inp)

    if not re.match(r'^\d{10,15}$', digits):
        reasons.append("Invalid phone number format"); score += 30
    elif len(digits) == 10 and not re.match(r'^[6-9]', digits):
        reasons.append("Invalid starting digit for Indian mobile"); score += 25

    if re.match(r'^(\d)\1{7,}$', digits):
        reasons.append("Suspicious: repeated digits (e.g. 9999999999)"); score += 40
    if digits in ("1234567890","0987654321","9876543210"):
        reasons.append("Sequential number pattern — likely fake"); score += 40
    if re.match(r'^(140|160|155|1800|1860|1909)', digits):
        reasons.append("Matches premium-rate / telemarketing prefix"); score += 35

    kw_score, hits = keyword_score(inp)
    if hits:
        reasons.append(f"Contains suspicious keywords: {', '.join(hits)}"); score += kw_score

    known = is_known_scam(digits, "Phone")
    if known:
        reasons.append(f"In scam database — reported {known['reports']} time(s)"); score += 60

    return build_result(score, reasons)


# ── Website ───────────────────────────────────────────────────────
POPULAR_BRANDS = ["google","facebook","instagram","twitter","amazon","paypal",
                  "netflix","youtube","apple","microsoft","sbi","hdfc","icici",
                  "paytm","phonepe","flipkart","razorpay","zomato","swiggy"]
FREE_TLDS      = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".win"]
RISKY_TLDS     = [".cc",".su",".pw",".ws"]

def detect_website(inp):
    reasons, score = [], 0
    url_str = inp if inp.startswith("http") else "https://" + inp
    try:
        from urllib.parse import urlparse
        u = urlparse(url_str)
        hostname = u.hostname.lower() if u.hostname else ""
    except Exception:
        return build_result(60, ["Could not parse URL"])

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        reasons.append("IP-based URL instead of domain name"); score += 50
    if u.scheme == "http":
        reasons.append("No HTTPS — connection is unencrypted"); score += 20

    for tld in FREE_TLDS:
        if hostname.endswith(tld):
            reasons.append(f'Free TLD "{tld}" — common in phishing'); score += 35
    for tld in RISKY_TLDS:
        if hostname.endswith(tld):
            reasons.append(f'Suspicious TLD "{tld}"'); score += 25

    parts       = hostname.split(".")
    domain_name = parts[-2] if len(parts) >= 2 else hostname
    for brand in POPULAR_BRANDS:
        if domain_name != brand and len(domain_name) > 3 and levenshtein(domain_name, brand) <= 2:
            reasons.append(f'Possible typosquatting of "{brand}"'); score += 45
            break

    if len(parts) > 4:
        reasons.append("Unusually deep subdomain structure"); score += 20
    if len(inp) > 100:
        reasons.append("Very long URL — may be obfuscated"); score += 15

    kw_score, hits = keyword_score(inp)
    if hits:
        reasons.append(f"Suspicious keywords in URL: {', '.join(hits)}"); score += kw_score

    known = is_known_scam(hostname, "Website")
    if known:
        reasons.append(f"In scam database — reported {known['reports']} time(s)"); score += 70

    return build_result(score, reasons)


# ── WhatsApp ──────────────────────────────────────────────────────
def detect_whatsapp(inp):
    reasons, score = [], 0
    is_link = "wa.me" in inp.lower() or "whatsapp" in inp.lower()
    if is_link:
        m = re.search(r'wa\.me/(\d+)', inp, re.I)
        if m and re.match(r'^(\d)\1{7,}$', m.group(1)):
            reasons.append("Repeated-digit number in WhatsApp link"); score += 40
        reasons.append("Direct WhatsApp link — used in social engineering"); score += 15
        kw_score, hits = keyword_score(inp)
        if hits:
            reasons.append(f"Suspicious keywords: {', '.join(hits)}"); score += kw_score
        digits = re.sub(r'\D', '', inp)
        known  = is_known_scam(digits, "WhatsApp")
        if known:
            reasons.append(f"In scam database — reported {known['reports']} time(s)"); score += 60
        return build_result(score, reasons)
    else:
        return detect_phone(inp)


# ── Instagram ─────────────────────────────────────────────────────
IMPERSONATION_SIGNALS = ["official","real_","_real","support","help",
                         "verified","admin","staff","giveaway","winner",
                         "crypto","invest","profit","account","service"]

def detect_instagram(inp):
    reasons, score = [], 0
    username = re.sub(r'^@|https?://(www\.)?instagram\.com/|/$', '', inp).lower()

    if not re.match(r'^[a-z0-9._]{1,30}$', username):
        reasons.append("Invalid Instagram username format"); score += 25

    underscores = username.count('_')
    if underscores >= 3:
        reasons.append(f"Too many underscores ({underscores}) — impersonation pattern"); score += 25

    hits = [s for s in IMPERSONATION_SIGNALS if s in username]
    if hits:
        reasons.append(f"Impersonation signals in username: {', '.join(hits)}")
        score += len(hits) * 20

    if re.search(r'[a-z]{3,}\d{6,}$', username):
        reasons.append("Username ends with many digits — likely a cloned account"); score += 30

    kw_score, kw_hits = keyword_score(username)
    if kw_hits:
        reasons.append(f"Suspicious keywords: {', '.join(kw_hits)}"); score += kw_score

    known = is_known_scam(username, "Instagram")
    if known:
        reasons.append(f"In scam database — reported {known['reports']} time(s)"); score += 60

    return build_result(score, reasons)


DETECTORS = {
    "Phone":     detect_phone,
    "WhatsApp":  detect_whatsapp,
    "Website":   detect_website,
    "Instagram": detect_instagram,
}


# ================================================================
#  PUBLIC API ROUTES
# ================================================================

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data  = request.get_json(force=True)
    inp   = (data.get("input") or "").strip()
    type_ = (data.get("type")  or "").strip()

    if not inp or type_ not in DETECTORS:
        return jsonify({"error": "input and valid type are required"}), 400

    result = DETECTORS[type_](inp)

    with get_db() as db:
        db.execute(
            "INSERT INTO scans (input,type,risk_level,threat,score,reasons) VALUES (?,?,?,?,?,?)",
            (inp, type_, result["risk_level"], 1 if result["threat"] else 0,
             result["score"], json.dumps(result["reasons"]))
        )

    return jsonify({"input": inp, "type": type_, **result})


@app.route("/api/report", methods=["POST"])
def api_report():
    if "user_id" not in session:
        return jsonify({"error": "login_required",
                        "message": "You must be logged in to report a scam."}), 401

    data     = request.get_json(force=True)
    inp      = (data.get("input")       or "").strip()
    type_    = (data.get("type")        or "").strip()
    desc     = (data.get("description") or "").strip()
    reporter = session.get("username", "unknown")

    if not inp or not type_:
        return jsonify({"error": "input and type are required"}), 400

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM known_scams WHERE LOWER(value)=? AND type=?",
            (inp.lower(), type_)
        ).fetchone()
        if existing:
            db.execute("UPDATE known_scams SET reports=reports+1 WHERE id=?",
                       (existing["id"],))
        else:
            db.execute(
                "INSERT INTO known_scams (value,type,description,source) VALUES (?,?,?,'user_report')",
                (inp.lower(), type_, desc)
            )
        db.execute(
            "INSERT INTO reports (input,type,description,reported_by) VALUES (?,?,?,?)",
            (inp, type_, desc, reporter)
        )

    return jsonify({"success": True,
                    "message": f"Report received. Thank you, {reporter}!"})


@app.route("/api/live-feed")
def api_live_feed():
    with get_db() as db:
        rows = db.execute("""
            SELECT id, input, type, risk_level, threat, scanned_at
            FROM scans ORDER BY id DESC LIMIT 20
        """).fetchall()

    def mask(val, t):
        if t in ("Phone","WhatsApp"):
            digits = re.sub(r'\D','',val)
            return ('*' * max(0, len(digits)-4)) + digits[-4:] if len(digits)>4 else "****"
        if t == "Website":
            try:
                from urllib.parse import urlparse
                return urlparse("https://"+val if not val.startswith("http") else val).hostname or val
            except: return val
        return val

    feed = [{"id": r["id"], "input": mask(r["input"], r["type"]),
             "type": r["type"], "risk_level": r["risk_level"],
             "threat": bool(r["threat"]), "scanned_at": r["scanned_at"]}
            for r in rows]
    return jsonify(feed)


@app.route("/api/stats")
def api_stats():
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        threats = db.execute("SELECT COUNT(*) FROM scans WHERE threat=1").fetchone()[0]
        reports = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        db_size = db.execute("SELECT COUNT(*) FROM known_scams").fetchone()[0]
        by_type = db.execute(
            "SELECT type, COUNT(*) as n FROM scans GROUP BY type"
        ).fetchall()
    return jsonify({
        "total": total, "threats": threats,
        "reports": reports, "db_entries": db_size,
        "by_type": [dict(r) for r in by_type]
    })


# ================================================================
#  USER AUTH — login, register, logout
# ================================================================

@app.route("/api/auth/status")
def auth_status():
    if "user_id" in session:
        return jsonify({"logged_in": True, "username": session["username"]})
    return jsonify({"logged_in": False, "username": None})


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(_safe_redirect(request.args.get("next", "/")))

    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        next_page = request.form.get("next", "/")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE LOWER(username)=?",
                (username.lower(),)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.permanent  = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            dest = "/?report=1" if next_page == "report" else _safe_redirect(next_page)
            return redirect(dest)
        else:
            flash("Incorrect username or password.", "error")
            return render_template("login.html", next=next_page)

    return render_template("login.html", next=request.args.get("next", "/"))


@app.route("/register", methods=["POST"])
def register():
    username  = request.form.get("username", "").strip()
    password  = request.form.get("password", "")
    confirm   = request.form.get("confirm",  "")
    next_page = request.form.get("next", "/")

    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        flash("Username must be 3–30 characters (letters, numbers, underscores).", "error")
        return render_template("login.html", next=next_page)
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return render_template("login.html", next=next_page)
    if password != confirm:
        flash("Passwords do not match.", "error")
        return render_template("login.html", next=next_page)

    with get_db() as db:
        if db.execute("SELECT id FROM users WHERE LOWER(username)=?",
                      (username.lower(),)).fetchone():
            flash("That username is already taken.", "error")
            return render_template("login.html", next=next_page)

        db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                   (username, generate_password_hash(password)))
        user = db.execute("SELECT * FROM users WHERE LOWER(username)=?",
                          (username.lower(),)).fetchone()

    session.permanent  = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    flash(f"Welcome, {username}! Your account has been created.", "success")
    dest = "/?report=1" if next_page == "report" else _safe_redirect(next_page)
    return redirect(dest)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    flash("You have been logged out.", "info")
    return redirect("/")


def _safe_redirect(url):
    """Prevent open-redirect — only allow relative paths."""
    if url and url.startswith("/") and not url.startswith("//"):
        return url
    return "/"


# ================================================================
#  HOME PAGE
# ================================================================

@app.route("/")
def home():
    return render_template("index.html")


# ================================================================
#  ADMIN PANEL — every route protected by @admin_required
# ================================================================

@app.route("/admin")
@admin_required
def admin():
    type_filter = request.args.get("type", "all")
    search      = request.args.get("search", "").strip()
    page        = max(1, int(request.args.get("page", 1)))
    per_page    = 20

    with get_db() as db:
        conditions, params = [], []
        if type_filter != "all":
            conditions.append("type=?"); params.append(type_filter)
        if search:
            conditions.append("(LOWER(value) LIKE ? OR LOWER(description) LIKE ?)")
            params += [f"%{search.lower()}%", f"%{search.lower()}%"]

        where      = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        total_rows = db.execute(f"SELECT COUNT(*) FROM known_scams {where}", params).fetchone()[0]
        offset     = (page - 1) * per_page
        rows       = db.execute(
            f"SELECT * FROM known_scams {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

        stats = {
            "total":     db.execute("SELECT COUNT(*) FROM known_scams").fetchone()[0],
            "phone":     db.execute("SELECT COUNT(*) FROM known_scams WHERE type='Phone'").fetchone()[0],
            "whatsapp":  db.execute("SELECT COUNT(*) FROM known_scams WHERE type='WhatsApp'").fetchone()[0],
            "website":   db.execute("SELECT COUNT(*) FROM known_scams WHERE type='Website'").fetchone()[0],
            "instagram": db.execute("SELECT COUNT(*) FROM known_scams WHERE type='Instagram'").fetchone()[0],
        }

        # Show recent user reports in admin panel
        recent_reports = db.execute(
            "SELECT * FROM reports ORDER BY id DESC LIMIT 10"
        ).fetchall()

    return render_template("admin.html",
        rows=rows, stats=stats,
        type_filter=type_filter, search=search,
        page=page, total_pages=max(1, -(-total_rows // per_page)),
        total_rows=total_rows,
        recent_reports=recent_reports,
        admin_username=session.get("admin_username", ADMIN_USERNAME)
    )


@app.route("/admin/add-bulk", methods=["POST"])
@admin_required
def admin_add_bulk():
    rows  = request.get_json(force=True).get("rows", [])
    added, skipped, errors = 0, 0, []

    with get_db() as db:
        for i, row in enumerate(rows):
            value = str(row.get("value", "")).strip()
            type_ = str(row.get("type",  "")).strip()
            desc  = str(row.get("description", "")).strip()
            src   = str(row.get("source", "")).strip() or "excel_import"

            if not value or type_ not in ("Phone","WhatsApp","Website","Instagram"):
                errors.append(f"Row {i+1}: invalid value or type '{type_}'")
                skipped += 1
                continue
            try:
                db.execute(
                    """INSERT INTO known_scams (value,type,description,source)
                       VALUES (?,?,?,?)
                       ON CONFLICT(value,type) DO UPDATE SET
                         reports=reports+1,
                         description=excluded.description""",
                    (value.lower(), type_, desc, src)
                )
                added += 1
            except Exception as e:
                errors.append(f"Row {i+1}: {str(e)}")
                skipped += 1

    return jsonify({"added": added, "skipped": skipped, "errors": errors})


@app.route("/admin/delete/<int:row_id>", methods=["POST"])
@admin_required
def admin_delete(row_id):
    with get_db() as db:
        db.execute("DELETE FROM known_scams WHERE id=?", (row_id,))
    return redirect(url_for("admin"))


@app.route("/admin/edit/<int:row_id>", methods=["POST"])
@admin_required
def admin_edit(row_id):
    value = request.form.get("value","").strip()
    type_ = request.form.get("type","").strip()
    desc  = request.form.get("description","").strip()
    if value and type_:
        with get_db() as db:
            db.execute(
                "UPDATE known_scams SET value=?,type=?,description=? WHERE id=?",
                (value.lower(), type_, desc, row_id)
            )
    return redirect(url_for("admin"))


@app.route("/admin/clear-type", methods=["POST"])
@admin_required
def admin_clear_type():
    type_ = request.form.get("type","")
    if type_ in ("Phone","WhatsApp","Website","Instagram"):
        with get_db() as db:
            db.execute("DELETE FROM known_scams WHERE type=?", (type_,))
    return redirect(url_for("admin"))


# ================================================================
#  ENTRY POINT
# ================================================================
if __name__ == "__main__":
    init_db()
    print("\n🔒 VERIFY360 Flask Backend")
    print(f"   Admin login  → http://localhost:5000/admin/login")
    print(f"   Admin user   → {ADMIN_USERNAME}")
    print(f"   Scan API     → POST http://localhost:5000/api/scan")
    print(f"   Live Feed    → GET  http://localhost:5000/api/live-feed\n")
    app.run(debug=True, port=5000)
