from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import mysql.connector
import os
from flask import g
import razorpay
import hmac
import hashlib
from flask_mail import Mail, Message
import random
import string
from datetime import datetime, timedelta
from datetime import datetime, date

# ============================================================
#  APP SETUP
# ============================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_in_production")

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "webm"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

RAZORPAY_KEY_ID     = "rzp_test_YOUR_KEY_ID"
RAZORPAY_KEY_SECRET = "YOUR_KEY_SECRET"

razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)

BOOST_PLANS = {
    "basic":    {"label": "Basic",    "days": 3,  "amount": 4900,  "display": "₹49"},
    "standard": {"label": "Standard", "days": 7,  "amount": 9900,  "display": "₹99"},
    "premium":  {"label": "Premium",  "days": 15, "amount": 19900, "display": "₹199"},
}

# ── EMAIL CONFIG ──────────────────────────────────────
app.config['MAIL_SERVER']   = 'smtp.gmail.com'
app.config['MAIL_PORT']     = 587
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = "official13301330@gmail.com"   # your Gmail
app.config['MAIL_PASSWORD'] = "mktt nrwy toma aybt"         # Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'Ampibians <your_app_email@gmail.com>'

mail = Mail(app)

# temporary OTP store — {email: {otp, expires_at, form_data}}
otp_store = {}

# ============================================================
#  DATABASE  — one connection pool per app
# ============================================================

DB_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "127.0.0.1"),
    "user":     os.environ.get("DB_USER",     "root"),
    "password": os.environ.get("DB_PASSWORD", "officialdream@43"),
    "database": os.environ.get("DB_NAME",     "Kascalo"),
}

def get_db():
    """Return a fresh connection. Call inside every route, close when done."""
    return mysql.connector.connect(**DB_CONFIG)


# ============================================================
#  HELPERS
# ============================================================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file):
    """Save an uploaded file and return (image_filename, video_filename)."""
    image_filename = None
    video_filename = None

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        ext = filename.rsplit(".", 1)[-1].lower()
        if ext in {"png", "jpg", "jpeg", "gif", "webp"}:
            image_filename = filename
        elif ext in {"mp4", "mov", "avi", "webm"}:
            video_filename = filename

    return image_filename, video_filename


def days_since(dt):
    return (datetime.now() - dt).days


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated


# ============================================================
#  AUTH  —  LOGIN / REGISTER / LOGOUT
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect("/feed")

    error = None

    if request.method == "POST":

        action   = request.form.get("action")
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        db  = get_db()
        cur = db.cursor(dictionary=True)

        # ── LOGIN ──────────────────────────────────────────
        if action == "login":

            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            if user and check_password_hash(user["password"], password):
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session["location"] = user["location"]
                cur.close(); db.close()
                return redirect("/feed")
            else:
                error = "Invalid email or password"

        # ── REGISTER ───────────────────────────────────────
        elif action == "register":

            username = request.form.get("username", "").strip()
            phone = request.form.get("phone", "").strip()
            category = request.form.get("category", "")
            location = request.form.get("location", "").strip()
            company_name = request.form.get("company_name")
            map_link = request.form.get("map_link")
            business_name = request.form.get("business_name")
            service_type = request.form.get("service_type")
            business_mode = request.form.get("business_mode")
            service_description = request.form.get("service_description")
            shop_name = request.form.get("shop_name")
            shop_type = request.form.get("shop_type")

            # check OTP was verified
            record = otp_store.get(email.lower())
            if not record or not record.get("verified"):
                error = "Please verify your email with the OTP before registering."
            else:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    error = "An account with this email already exists."
                else:
                    hashed = generate_password_hash(password)
                    cur.execute("""
                        INSERT INTO users (
                            username, email, phone, category, location, password,
                            company_name, map_link,
                            business_name, service_type, business_mode, service_description,
                            shop_name, shop_type
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (
                        username, email, phone, category, location, hashed,
                        company_name, map_link,
                        business_name, service_type, business_mode, service_description,
                        shop_name, shop_type
                    ))
                    db.commit()

                    # clean up OTP
                    otp_store.pop(email.lower(), None)

                    session["user_id"] = cur.lastrowid
                    session["username"] = username
                    session["location"] = location

                    cur.close();
                    db.close()
                    return redirect("/feed")

        cur.close(); db.close()

    return render_template("login.html", error=error)


@app.route("/send_otp", methods=["POST"])
def send_otp():
    data  = request.get_json()
    email = (data.get("email") or "").strip().lower()

    # validate it looks like a real email
    import re
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({"success": False, "error": "Please enter a valid email address."})

    # check not already registered
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        cur.close(); db.close()
        return jsonify({"success": False, "error": "This email is already registered."})
    cur.close(); db.close()

    # generate 6-digit OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[email] = {
        "otp":        otp,
        "expires_at": datetime.now() + timedelta(minutes=10)
    }

    # send email
    try:
        msg = Message(
            subject = "Your Ampibians verification code",
            recipients = [email],
            html = f"""
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#1a1917;border-radius:12px;">
                <h2 style="color:#e8622a;font-size:24px;margin-bottom:8px;">Ampibians</h2>
                <p style="color:#f0ece4;font-size:16px;margin-bottom:24px;">Your verification code is:</p>
                <div style="background:#242220;border:2px solid #e8622a;border-radius:10px;
                            padding:20px;text-align:center;margin-bottom:24px;">
                    <span style="font-size:40px;font-weight:800;letter-spacing:12px;color:#f0ece4;">
                        {otp}
                    </span>
                </div>
                <p style="color:#7a756c;font-size:13px;">This code expires in 10 minutes.<br>
                If you didn't request this, ignore this email.</p>
            </div>
            """
        )
        mail.send(msg)
        return jsonify({"success": True})
    except Exception as e:
        print("[OTP EMAIL ERROR]", e)
        return jsonify({"success": False, "error": "Failed to send email. Check your email address."})


@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data  = request.get_json()
    email = (data.get("email") or "").strip().lower()
    otp   = (data.get("otp") or "").strip()

    record = otp_store.get(email)
    if not record:
        return jsonify({"success": False, "error": "No OTP found. Please request a new one."})

    if datetime.now() > record["expires_at"]:
        otp_store.pop(email, None)
        return jsonify({"success": False, "error": "OTP expired. Please request a new one."})

    if record["otp"] != otp:
        return jsonify({"success": False, "error": "Incorrect code. Please try again."})

    # mark verified
    otp_store[email]["verified"] = True
    return jsonify({"success": True})


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
#  PROFILE
# ============================================================

'''@app.route("/profile")
@login_required
def profile():

    db  = get_db()
    cur = db.cursor(dictionary=True)
    uid = session["user_id"]

    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    user = cur.fetchone()

    # general posts
    cur.execute("""
        SELECT id, content, type, location, image, created_at, 'post' AS post_type
        FROM posts WHERE user_id = %s
    """, (uid,))
    rows_posts = cur.fetchall()

    # jobs
    cur.execute("""
        SELECT id, job_title AS content, employment_type AS type,
               walkin_location AS location, NULL AS image, created_at, 'job' AS post_type
        FROM jobs WHERE user_id = %s
    """, (uid,))
    rows_jobs = cur.fetchall()

    # services
    cur.execute("""
        SELECT id, COALESCE(company_name, shop_name, 'Business') AS content,
               category AS type, location, image, created_at, 'service' AS post_type
        FROM services WHERE user_id = %s
    """, (uid,))
    rows_services = cur.fetchall()

    # events
    cur.execute("""
        SELECT id, event_title AS content, 'event' AS type,
               place AS location, image, created_at, 'event' AS post_type
        FROM events WHERE user_id = %s
    """, (uid,))
    rows_events = cur.fetchall()

    # alerts
    cur.execute("""
        SELECT id, title AS content, alert_type AS type,
               location, image, created_at, 'alert' AS post_type
        FROM alerts WHERE user_id = %s
    """, (uid,))
    rows_alerts = cur.fetchall()

    cur.close(); db.close()

    # merge + deduplicate by (post_type, id)
    combined = rows_posts + rows_jobs + rows_services + rows_events + rows_alerts
    seen     = set()
    all_posts = []
    for p in combined:
        key = (p["post_type"], p["id"])
        if key not in seen:
            seen.add(key)
            all_posts.append(p)

    all_posts.sort(key=lambda x: x["created_at"], reverse=True)

    print(f"[PROFILE] uid={uid} total={len(all_posts)}")

    return render_template("profile.html", user=user, posts=all_posts)'''

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    user_id = session['user_id']
    cur = db.cursor(dictionary=True)

    # ─── 1. FETCH USER ─────────────────────────────────────────
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    if not user:
        cur.close()
        return redirect('/login')

    # ─── 2. FETCH USER'S OWN POSTS (all types in one list) ─────
    posts = []

    # General posts
    cur.execute("""
        SELECT id, content, image, location, created_at, 'post' AS post_type
        FROM posts WHERE user_id = %s
    """, (user_id,))
    posts += cur.fetchall()

    # Jobs
    cur.execute("""
        SELECT id, job_title AS content, company_logo AS image,
               NULL AS location, created_at, 'job' AS post_type
        FROM jobs WHERE user_id = %s
    """, (user_id,))
    posts += cur.fetchall()

    # Services
    cur.execute("""
        SELECT id,
               COALESCE(company_name, shop_name, 'Service') AS content,
               image, NULL AS location, created_at, 'service' AS post_type
        FROM services WHERE user_id = %s
    """, (user_id,))
    posts += cur.fetchall()

    # Events
    cur.execute("""
        SELECT id, event_title AS content, image,
               place AS location, created_at, 'event' AS post_type
        FROM events WHERE user_id = %s
    """, (user_id,))
    posts += cur.fetchall()

    # Alerts
    cur.execute("""
        SELECT id, title AS content, image, NULL AS location,
               created_at, 'alert' AS post_type
        FROM alerts WHERE user_id = %s
    """, (user_id,))
    posts += cur.fetchall()

    # Newest first
    posts.sort(key=lambda x: x.get('created_at') or 0, reverse=True)

    # ─── 3. FETCH SAVED ITEMS ──────────────────────────────────
    saved_posts = []

    cur.execute("""
        SELECT p.id, p.content, p.image, p.location, p.created_at,
               'post' AS post_type, u.username, u.profile_image, sp.saved_at
        FROM saved_posts sp
        JOIN posts p ON p.id = sp.post_id
        JOIN users u ON u.id = p.user_id
        WHERE sp.user_id=%s AND sp.post_type='post'
    """, (user_id,))
    saved_posts += cur.fetchall()

    cur.execute("""
        SELECT j.id, j.job_title AS content, j.company_logo AS image,
               NULL AS location, j.created_at,
               'job' AS post_type, u.username, u.profile_image, sp.saved_at
        FROM saved_posts sp
        JOIN jobs j ON j.id = sp.post_id
        JOIN users u ON u.id = j.user_id
        WHERE sp.user_id=%s AND sp.post_type='job'
    """, (user_id,))
    saved_posts += cur.fetchall()

    cur.execute("""
        SELECT s.id,
               COALESCE(s.company_name, s.shop_name, 'Service') AS content,
               s.image, NULL AS location, s.created_at,
               'service' AS post_type, u.username, u.profile_image, sp.saved_at
        FROM saved_posts sp
        JOIN services s ON s.id = sp.post_id
        JOIN users u ON u.id = s.user_id
        WHERE sp.user_id=%s AND sp.post_type='service'
    """, (user_id,))
    saved_posts += cur.fetchall()

    cur.execute("""
        SELECT e.id, e.event_title AS content, e.image,
               e.place AS location, e.created_at,
               'event' AS post_type, u.username, u.profile_image, sp.saved_at
        FROM saved_posts sp
        JOIN events e ON e.id = sp.post_id
        JOIN users u ON u.id = e.user_id
        WHERE sp.user_id=%s AND sp.post_type='event'
    """, (user_id,))
    saved_posts += cur.fetchall()

    cur.execute("""
        SELECT a.id, a.title AS content, a.image, NULL AS location, a.created_at,
               'alert' AS post_type, u.username, u.profile_image, sp.saved_at
        FROM saved_posts sp
        JOIN alerts a ON a.id = sp.post_id
        JOIN users u ON u.id = a.user_id
        WHERE sp.user_id=%s AND sp.post_type='alert'
    """, (user_id,))
    saved_posts += cur.fetchall()

    saved_posts.sort(key=lambda x: x.get('saved_at') or 0, reverse=True)

    cur.close()

    return render_template('profile.html',
                           user=user,
                           posts=posts,
                           saved_posts=saved_posts)


@app.route("/update_banner", methods=["POST"])
@login_required
def update_banner():
    file = request.files.get("image")
    if file and file.filename != "":
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE users SET banner_image = %s WHERE id = %s",
            (filename, session["user_id"])
        )
        db.commit()
        cur.close(); db.close()
    return redirect("/profile")

@app.context_processor
def inject_user():
    if "user_id" not in session:
        return {"current_user": None}

    # use g to avoid querying multiple times per request
    if not hasattr(g, "current_user"):
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, profile_image, location FROM users WHERE id = %s",
            (session["user_id"],)
        )
        g.current_user = cur.fetchone()
        cur.close(); db.close()

    return {"current_user": g.current_user}


@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():

    file = request.files.get("image")

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE users SET profile_image = %s WHERE id = %s",
            (filename, session["user_id"])
        )
        db.commit()
        cur.close(); db.close()

    return redirect("/profile")


# ============================================================
#  FEED  (alerts + events + jobs + services combined view)
# ============================================================

'''@app.route("/feed")
@login_required
def feed():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    # current user
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()

    user_location = session.get("location", "")

    # ── general posts (alerts, community) ─────────────────
    cur.execute("""
        SELECT posts.*, users.username, users.profile_image, 'post' AS feed_type
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.location = %s
        ORDER BY posts.created_at DESC
    """, (user_location,))
    posts = cur.fetchall()

    # ── jobs ───────────────────────────────────────────────
    cur.execute("""
        SELECT jobs.*, users.username, users.profile_image, 'job' AS feed_type
        FROM jobs
        JOIN users ON jobs.user_id = users.id
        WHERE jobs.walkin_location = %s OR %s = ''
        ORDER BY jobs.created_at DESC
    """, (user_location, user_location))
    jobs = cur.fetchall()

    # ── events ───────────────────────────────────────────
    cur.execute("""
        SELECT events.*, users.username, users.profile_image, 'event' AS feed_type
        FROM events
        JOIN users ON events.user_id = users.id
        ORDER BY events.event_date ASC
    """)
    events = cur.fetchall()

    # combine + sort
    feed_data = posts + jobs + events
    feed_data.sort(key=lambda x: x["created_at"], reverse=True)

    for item in feed_data:
        item["days_live"] = days_since(item["created_at"])

    cur.close(); db.close()
    return render_template("feed.html", user=user, posts=feed_data)'''

@app.route("/feed")
@login_required
def feed():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    # expire any boosts that have ended — run on every feed load
    # expire boosts — only for the 3 boostable tables
    for table in ["jobs", "services", "events"]:
        cur.execute(f"""
            UPDATE {table}
            SET is_featured = FALSE
            WHERE is_featured = TRUE
              AND boost_expires_at IS NOT NULL
              AND boost_expires_at < NOW()
        """)
    db.commit()

    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()

    # ── general posts ─────────────────────────────────
    # ── general posts (no is_featured — not boostable) ────
    cur.execute("""
        SELECT posts.*, users.username, users.profile_image, 'post' AS feed_type
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """)
    posts = cur.fetchall()

    for post in posts:
        cur.execute(
            "SELECT COUNT(*) AS total FROM likes WHERE post_id = %s",
            (post["id"],)
        )
        post["likes_count"] = cur.fetchone()["total"]

        cur.execute(
            "SELECT id FROM likes WHERE user_id = %s AND post_id = %s",
            (session["user_id"], post["id"])
        )
        post["liked"] = bool(cur.fetchone())

    # ── jobs ──────────────────────────────────────────────
    cur.execute("""
        SELECT jobs.*, users.username, users.profile_image, 'job' AS feed_type
        FROM jobs
        JOIN users ON jobs.user_id = users.id
        ORDER BY jobs.is_featured DESC, jobs.created_at DESC
    """)
    jobs = cur.fetchall()

    # ── events ────────────────────────────────────────────
    cur.execute("""
        SELECT events.*, users.username, users.profile_image, 'event' AS feed_type
        FROM events
        JOIN users ON events.user_id = users.id
        ORDER BY events.is_featured DESC, events.event_date ASC
    """)
    events = cur.fetchall()

    # ── services ──────────────────────────────────────────
    cur.execute("""
        SELECT services.*, users.username, users.profile_image, 'service' AS feed_type
        FROM services
        JOIN users ON services.user_id = users.id
        ORDER BY services.is_featured DESC, services.created_at DESC
    """)
    services = cur.fetchall()

    # ── alerts (no is_featured — not boostable) ───────────
    cur.execute("""
        SELECT alerts.*, users.username, users.profile_image, 'alert' AS feed_type
        FROM alerts
        JOIN users ON alerts.user_id = users.id
        ORDER BY alerts.created_at DESC
    """)
    alerts = cur.fetchall()

    # combine — featured items float to top, rest sorted by time
    feed_data = posts + jobs + events + services + alerts
    feed_data.sort(key=lambda x: (
        0 if x.get("is_featured") else 1,   # featured first
        x["created_at"]                      # then newest
    ), reverse=False)

    # flip non-featured by time (newest first within featured=0 group)
    featured     = [x for x in feed_data if x.get("is_featured")]
    non_featured = [x for x in feed_data if not x.get("is_featured")]
    non_featured.sort(key=lambda x: x["created_at"], reverse=True)
    feed_data = featured + non_featured

    for item in feed_data:
        item["days_live"] = days_since(item["created_at"])

    cur.close(); db.close()
    return render_template("feed.html", user=user, posts=feed_data)


# ============================================================
#  CREATE POST  (alerts / community notices)
# ============================================================

@app.route("/create_post", methods=["GET", "POST"])
@login_required
def create_post():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()

    if request.method == "POST":

        content  = request.form.get("content", "")
        type_    = request.form.get("type", "general")
        location = request.form.get("location", session.get("location", ""))

        media = request.files.get("media")
        image_filename, video_filename = save_upload(media)



        cur.execute("""
            INSERT INTO posts (user_id, content, type, location, image, video)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session["user_id"], content, type_, location, image_filename, video_filename))
        db.commit()

        cur.close(); db.close()
        return redirect("/feed")


    cur.close(); db.close()
    return render_template("create_post.html", user=user)

@app.route("/post/<int:post_id>")
@login_required
def view_post(post_id):

    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        SELECT posts.*, users.username, users.profile_image
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = %s
    """, (post_id,))
    post = cur.fetchone()

    cur.close(); db.close()

    if not post:
        return "Post not found", 404

    return render_template("single_post.html", post=post)

@app.route("/delete_post/<int:post_id>/<feed_type>", methods=["POST"])
@login_required
def delete_post(post_id, feed_type):

    db  = get_db()
    cur = db.cursor()

    if feed_type == "job":
        cur.execute(
            "DELETE FROM jobs WHERE id = %s AND user_id = %s",
            (post_id, session["user_id"])
        )
    elif feed_type == "event":
        cur.execute(
            "DELETE FROM events WHERE id = %s AND user_id = %s",
            (post_id, session["user_id"])
        )
    else:
        cur.execute(
            "DELETE FROM posts WHERE id = %s AND user_id = %s",
            (post_id, session["user_id"])
        )

    db.commit()
    cur.close(); db.close()

    return jsonify({"success": True})


# ============================================================
#  SERVICES  (business & service directory)
# ============================================================

'''@app.route("/services", methods=["GET", "POST"])
@login_required
def services():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        content             = request.form.get("content")
        location            = request.form.get("location", "").strip() or session.get("location", "")
        phone               = request.form.get("phone")
        website             = request.form.get("website")
        category            = request.form.get("category")
        business_mode       = request.form.get("business_mode")
        company_name        = request.form.get("company_name")
        service_type        = request.form.get("service_type")
        map_link            = request.form.get("map_link")
        service_description = request.form.get("service_description")
        shop_name           = request.form.get("shop_name")
        shop_type           = request.form.get("shop_type")
        shop_map_link       = request.form.get("shop_map_link")
        shop_description    = request.form.get("shop_description")
        bio                 = request.form.get("bio")

        file = request.files.get("image")
        filename = None
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        try:
            cur.execute("""
                INSERT INTO services (
                    user_id, content, category, location, phone, website, image,
                    business_mode, company_name, service_type, map_link,
                    service_description, shop_name, shop_type, shop_map_link,
                    shop_description, bio
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                session["user_id"], content, category, location, phone, website, filename,
                business_mode, company_name, service_type, map_link,
                service_description, shop_name, shop_type, shop_map_link,
                shop_description, bio
            ))
            db.commit()
            print("[SERVICE] Inserted successfully, id:", cur.lastrowid)

        except Exception as e:
            print("[SERVICE ERROR]", e)
            cur.close(); db.close()
            return f"<h2>DB Error</h2><pre>{e}</pre>", 500

        cur.close(); db.close()
        return redirect("/services")

    # GET — show all services
    cur.execute("""
        SELECT services.*, users.username, users.profile_image
        FROM services
        JOIN users ON services.user_id = users.id
        ORDER BY services.created_at DESC
    """)
    service_list = cur.fetchall()

    cur.close(); db.close()
    return render_template("services.html", services=service_list)'''

@app.route("/services", methods=["GET", "POST"])
@login_required
def services():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        want_boost          = request.form.get("want_boost") == "yes"
        content             = request.form.get("content")
        location            = request.form.get("location", "").strip() or session.get("location", "")
        phone               = request.form.get("phone")
        website             = request.form.get("website")
        category            = request.form.get("category")
        business_mode       = request.form.get("business_mode")
        company_name        = request.form.get("company_name")
        service_type        = request.form.get("service_type")
        map_link            = request.form.get("map_link")
        service_description = request.form.get("service_description")
        shop_name           = request.form.get("shop_name")
        shop_type           = request.form.get("shop_type")
        shop_map_link       = request.form.get("shop_map_link")
        shop_description    = request.form.get("shop_description")
        bio                 = request.form.get("bio")

        file = request.files.get("image")
        filename = None
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        try:
            cur.execute("""
                INSERT INTO services (
                    user_id, content, category, location, phone, website, image,
                    business_mode, company_name, service_type, map_link,
                    service_description, shop_name, shop_type, shop_map_link,
                    shop_description, bio
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                session["user_id"], content, category, location, phone, website, filename,
                business_mode, company_name, service_type, map_link,
                service_description, shop_name, shop_type, shop_map_link,
                shop_description, bio
            ))
            db.commit()
            new_id = cur.lastrowid

            # after getting company_name/shop_name, before INSERT:
            name_check = company_name or shop_name or ""
            cur.execute("""
                SELECT id FROM services
                WHERE user_id = %s
                AND (company_name = %s OR shop_name = %s)
                AND created_at > NOW() - INTERVAL 30 SECOND
            """, (session["user_id"], name_check, name_check))

            if cur.fetchone():
                cur.close();
                db.close()
                return redirect("/services")

        except Exception as e:
            print("[SERVICE ERROR]", e)
            cur.close(); db.close()
            return f"<h2>DB Error</h2><pre>{e}</pre>", 500

        cur.close(); db.close()

        if want_boost:
            return redirect(f"/boost/service/{new_id}")
        return redirect("/services")


    cur.execute("""
        SELECT services.*, users.username, users.profile_image
        FROM services
        JOIN users ON services.user_id = users.id
        ORDER BY services.created_at DESC
    """)
    service_list = cur.fetchall()

    cur.close(); db.close()
    return render_template("services.html", services=service_list)


@app.route("/delete_service/<int:service_id>", methods=["POST"])
@login_required
def delete_service(service_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "DELETE FROM services WHERE id = %s AND user_id = %s",
        (service_id, session["user_id"])
    )
    db.commit()
    cur.close(); db.close()
    return redirect("/services")


# ============================================================
#  JOBS
# ============================================================

'''@app.route("/jobs", methods=["GET", "POST"])
@login_required
def jobs():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        recruiter_name    = request.form.get("recruiter_name")
        organization_name = request.form.get("organization_name")
        job_title         = request.form.get("job_title")
        experience        = request.form.get("experience")
        employment_type   = request.form.get("employment_type")
        job_description   = request.form.get("job_description")
        hiring_type       = request.form.get("hiring_type")
        walkin_date       = request.form.get("walkin_date") or None
        walkin_start      = request.form.get("walkin_start") or None
        walkin_end        = request.form.get("walkin_end") or None
        walkin_location   = request.form.get("walkin_location")
        apply_link        = request.form.get("apply_link")

        cur.execute("""
            INSERT INTO jobs (
                user_id, recruiter_name, organization_name, job_title, experience,
                employment_type, job_description, hiring_type,
                walkin_date, walkin_start, walkin_end, walkin_location, apply_link
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"], recruiter_name, organization_name, job_title, experience,
            employment_type, job_description, hiring_type,
            walkin_date, walkin_start, walkin_end, walkin_location, apply_link
        ))
        db.commit()

        cur.close(); db.close()
        return redirect("/jobs")

    # GET
    cur.execute("""
        SELECT jobs.*, users.username, users.profile_image
        FROM jobs
        JOIN users ON jobs.user_id = users.id
        ORDER BY jobs.created_at DESC
    """)
    job_list = cur.fetchall()

    for job in job_list:
        job["days_live"] = days_since(job["created_at"])

    cur.close(); db.close()
    return render_template("jobs.html", jobs=job_list)'''

'''@app.route("/jobs", methods=["GET", "POST"])
@login_required
def jobs():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        want_boost        = request.form.get("want_boost") == "yes"
        recruiter_name    = request.form.get("recruiter_name")
        organization_name = request.form.get("organization_name")
        job_title         = request.form.get("job_title", "").strip()
        experience        = request.form.get("experience")
        employment_type   = request.form.get("employment_type")
        job_description   = request.form.get("job_description")
        hiring_type       = request.form.get("hiring_type")
        walkin_date       = request.form.get("walkin_date") or None
        walkin_start      = request.form.get("walkin_start") or None
        walkin_end        = request.form.get("walkin_end") or None
        walkin_location   = request.form.get("walkin_location")
        apply_link        = request.form.get("apply_link")

        # company logo upload
        logo_filename = None
        logo_file = request.files.get("company_logo")
        if logo_file and logo_file.filename != "":
            logo_filename = secure_filename(logo_file.filename)
            logo_file.save(os.path.join(app.config["UPLOAD_FOLDER"], logo_filename))

        # duplicate check BEFORE insert
        cur.execute("""
            SELECT id FROM jobs
            WHERE user_id = %s AND job_title = %s
            AND created_at > NOW() - INTERVAL 30 SECOND
        """, (session["user_id"], job_title))

        if cur.fetchone():
            cur.close(); db.close()
            return redirect("/jobs")

        cur.execute("""
            INSERT INTO jobs (
                user_id, recruiter_name, organization_name, job_title, experience,
                employment_type, job_description, hiring_type,
                walkin_date, walkin_start, walkin_end, walkin_location,
                apply_link, company_logo
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"], recruiter_name, organization_name, job_title, experience,
            employment_type, job_description, hiring_type,
            walkin_date, walkin_start, walkin_end, walkin_location,
            apply_link, logo_filename
        ))
        db.commit()
        new_id = cur.lastrowid
        cur.close(); db.close()

        if want_boost:
            return redirect(f"/boost/job/{new_id}")
        return redirect("/jobs")

    cur.execute("""
        SELECT jobs.*, users.username, users.profile_image
        FROM jobs
        JOIN users ON jobs.user_id = users.id
        ORDER BY jobs.is_featured DESC, jobs.created_at DESC
    """)
    job_list = cur.fetchall()

    for job in job_list:
        job["days_live"] = days_since(job["created_at"])

    cur.close(); db.close()
    return render_template("jobs.html", jobs=job_list)'''


@app.route("/jobs", methods=["GET", "POST"])
@login_required
def jobs():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        want_boost        = request.form.get("want_boost") == "yes"
        recruiter_name    = request.form.get("recruiter_name")
        organization_name = request.form.get("organization_name")
        job_title         = request.form.get("job_title", "").strip()
        experience        = request.form.get("experience")
        employment_type   = request.form.get("employment_type")
        job_description   = request.form.get("job_description")
        hiring_type        = request.form.get("hiring_type")
        walkin_date       = request.form.get("walkin_date") or None
        walkin_start      = request.form.get("walkin_start") or None
        walkin_end        = request.form.get("walkin_end") or None
        walkin_location   = request.form.get("walkin_location")
        apply_link        = request.form.get("apply_link")
        job_location      = request.form.get("job_location", "").strip() or session.get("location", "")

        logo_filename = None
        logo_file = request.files.get("company_logo")
        if logo_file and logo_file.filename != "":
            logo_filename = secure_filename(logo_file.filename)
            logo_file.save(os.path.join(app.config["UPLOAD_FOLDER"], logo_filename))

        cur.execute("""
            SELECT id FROM jobs
            WHERE user_id = %s AND job_title = %s
            AND created_at > NOW() - INTERVAL 30 SECOND
        """, (session["user_id"], job_title))

        if cur.fetchone():
            cur.close(); db.close()
            return redirect("/jobs")

        cur.execute("""
            INSERT INTO jobs (
                user_id, recruiter_name, organization_name, job_title, experience,
                employment_type, job_description, hiring_type,
                walkin_date, walkin_start, walkin_end, walkin_location,
                apply_link, company_logo, location
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"], recruiter_name, organization_name, job_title, experience,
            employment_type, job_description, hiring_type,
            walkin_date, walkin_start, walkin_end, walkin_location,
            apply_link, logo_filename, job_location
        ))
        db.commit()
        new_id = cur.lastrowid
        cur.close(); db.close()

        if want_boost:
            return redirect(f"/boost/job/{new_id}")
        return redirect("/jobs")

    cur.execute("""
        SELECT jobs.*, users.username, users.profile_image
        FROM jobs
        JOIN users ON jobs.user_id = users.id
        ORDER BY jobs.is_featured DESC, jobs.created_at DESC
    """)
    job_list = cur.fetchall()

    for job in job_list:
        job["days_live"] = days_since(job["created_at"])

    # distinct locations for filter dropdown
    cur.execute("""
        SELECT DISTINCT location FROM jobs
        WHERE location IS NOT NULL AND location != ''
        ORDER BY location ASC
    """)
    locations = [row["location"] for row in cur.fetchall()]

    cur.close(); db.close()
    return render_template("jobs.html", jobs=job_list, locations=locations)

'''@app.route("/apply_job/<int:job_id>")
@login_required
def apply_job(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute(
            "INSERT INTO job_interactions (user_id, job_id, interaction_type) VALUES (%s, %s, 'apply')",
            (session["user_id"], job_id)
        )
        cur.execute(
            "UPDATE jobs SET applied_count = applied_count + 1 WHERE id = %s",
            (job_id,)
        )
        db.commit()
        print(f"[APPLY] user={session['user_id']} job={job_id} rows_affected={cur.rowcount}")
    except Exception as e:
        print(f"[APPLY ERROR] {e}")
        db.rollback()
    cur.close(); db.close()
    return redirect("/jobs")'''

'''@app.route("/apply_job/<int:job_id>")
@login_required
def apply_job(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        UPDATE jobs SET applied_count = applied_count + 1
        WHERE id = %s
    """, (job_id,))

    # get job owner + title
    cur.execute("""
        SELECT jobs.user_id, jobs.job_title, users.username AS applicant
        FROM jobs
        JOIN users ON users.id = %s
        WHERE jobs.id = %s
    """, (session["user_id"], job_id))
    row = cur.fetchone()
    db.commit()
    cur.close(); db.close()

    if row and row["user_id"] != session["user_id"]:
        create_notification(
            user_id = row["user_id"],
            type_   = "job_apply",
            title   = "New Job Application",
            body    = f"{row['applicant']} applied to your job: {row['job_title']}",
            link    = f"/jobs"
        )

    return redirect("/jobs")'''

@app.route("/apply_job/<int:job_id>", methods=["GET", "POST"])
@login_required
def apply_job(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
    job = cur.fetchone()
    if not job:
        cur.close(); db.close()
        return redirect("/jobs")

    # if job has a direct apply_link, skip the in-app form entirely
    if job.get("apply_link"):
        cur.close(); db.close()
        return redirect(job["apply_link"])

    if request.method == "POST":

        # prevent duplicate application
        cur.execute("""
            SELECT id FROM job_applications
            WHERE job_id = %s AND applicant_id = %s
        """, (job_id, session["user_id"]))
        if cur.fetchone():
            cur.close(); db.close()
            return redirect("/jobs?already_applied=1")

        full_name  = request.form.get("full_name", "").strip()
        email      = request.form.get("email", "").strip()
        phone      = request.form.get("phone", "").strip()
        cover_note = request.form.get("cover_note", "").strip()

        resume_filename = None
        resume_file = request.files.get("resume")
        if resume_file and resume_file.filename != "":
            ext = resume_file.filename.rsplit(".", 1)[-1].lower()
            if ext in ["pdf", "png", "jpg", "jpeg"]:
                resume_filename = secure_filename(
                    f"resume_{session['user_id']}_{job_id}_{resume_file.filename}"
                )
                resume_file.save(os.path.join(app.config["UPLOAD_FOLDER"], resume_filename))

        cur.execute("""
            INSERT INTO job_applications
                (job_id, applicant_id, full_name, email, phone, resume_file, cover_note)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (job_id, session["user_id"], full_name, email, phone,
              resume_filename, cover_note))
        application_id = cur.lastrowid

        # ── WORK EXPERIENCE ──
        work_companies = request.form.getlist("work_company[]")
        work_roles     = request.form.getlist("work_role[]")
        work_desc      = request.form.getlist("work_description[]")
        work_start     = request.form.getlist("work_start[]")
        work_end       = request.form.getlist("work_end[]")
        work_current   = request.form.getlist("work_current[]")

        for i in range(len(work_companies)):
            if work_companies[i].strip():
                cur.execute("""
                    INSERT INTO application_work_experience
                        (application_id, company_name, role, description,
                         start_date, end_date, is_current)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (application_id, work_companies[i], work_roles[i],
                      work_desc[i], work_start[i],
                      work_end[i] if i < len(work_end) else None, False))

        # ── INTERNSHIPS ──
        intern_companies = request.form.getlist("intern_company[]")
        intern_roles     = request.form.getlist("intern_role[]")
        intern_desc      = request.form.getlist("intern_description[]")
        intern_start     = request.form.getlist("intern_start[]")
        intern_end       = request.form.getlist("intern_end[]")

        for i in range(len(intern_companies)):
            if intern_companies[i].strip():
                cur.execute("""
                    INSERT INTO application_internships
                        (application_id, company_name, role, description, start_date, end_date)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (application_id, intern_companies[i], intern_roles[i],
                      intern_desc[i], intern_start[i],
                      intern_end[i] if i < len(intern_end) else None))

        # ── EDUCATION ──
        edu_colleges = request.form.getlist("edu_college[]")
        edu_courses  = request.form.getlist("edu_course[]")
        edu_years    = request.form.getlist("edu_year[]")

        for i in range(len(edu_colleges)):
            if edu_colleges[i].strip():
                cur.execute("""
                    INSERT INTO application_education
                        (application_id, college_name, course, completed_year)
                    VALUES (%s,%s,%s,%s)
                """, (application_id, edu_colleges[i], edu_courses[i], edu_years[i]))

        cur.execute("UPDATE jobs SET applied_count = applied_count + 1 WHERE id = %s", (job_id,))
        db.commit()
        cur.close(); db.close()

        # ── NOTIFY JOB OWNER / HR ──
        if job["user_id"] != session["user_id"]:
            create_notification(
                user_id = job["user_id"],
                type_   = "job_apply",
                title   = "New Job Application",
                body    = f"{full_name} applied to your job: {job['job_title']}",
                link    = f"/jobs/applications/{job_id}"
            )

        return redirect("/jobs?applied=1")

    cur.close(); db.close()
    return render_template("apply_job.html", job=job)

# ── VIEW APPLICATIONS (for job poster) ──
@app.route("/jobs/applications/<int:job_id>")
@login_required
def view_applications(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
    job = cur.fetchone()
    if not job or job["user_id"] != session["user_id"]:
        cur.close(); db.close()
        return "Access denied", 403

    cur.execute("""
        SELECT job_applications.*, users.username
        FROM job_applications
        JOIN users ON job_applications.applicant_id = users.id
        WHERE job_id = %s
        ORDER BY created_at DESC
    """, (job_id,))
    applications = cur.fetchall()

    for app_row in applications:
        cur.execute("SELECT * FROM application_work_experience WHERE application_id = %s",
                    (app_row["id"],))
        app_row["work_experience"] = cur.fetchall()

        cur.execute("SELECT * FROM application_internships WHERE application_id = %s",
                    (app_row["id"],))
        app_row["internships"] = cur.fetchall()

        cur.execute("SELECT * FROM application_education WHERE application_id = %s",
                    (app_row["id"],))
        app_row["education"] = cur.fetchall()

    cur.close(); db.close()
    return render_template("view_applications.html", job=job, applications=applications)


'''@app.route("/interested_job/<int:job_id>")
@login_required
def interested_job(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute(
            "INSERT INTO job_interactions (user_id, job_id, interaction_type) VALUES (%s, %s, 'interested')",
            (session["user_id"], job_id)
        )
        cur.execute(
            "UPDATE jobs SET interested_count = interested_count + 1 WHERE id = %s",
            (job_id,)
        )
        db.commit()
        print(f"[INTERESTED] user={session['user_id']} job={job_id} rows_affected={cur.rowcount}")
    except Exception as e:
        print(f"[INTERESTED ERROR] {e}")
        db.rollback()
    cur.close(); db.close()
    return redirect("/jobs")'''

@app.route("/interested_job/<int:job_id>")
@login_required
def interested_job(job_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
    job = cur.fetchone()

    if job:
        cur.execute("SELECT username FROM users WHERE id = %s", (session["user_id"],))
        applicant = cur.fetchone()

        cur.execute("UPDATE jobs SET interested_count = interested_count + 1 WHERE id = %s", (job_id,))
        db.commit()
        cur.close(); db.close()

        if job["user_id"] != session["user_id"]:
            create_notification(
                user_id = job["user_id"],
                type_   = "interested",
                title   = "Someone is Interested",
                body    = f"{applicant['username']} marked interest in your job: {job['job_title']}",
                link    = "/jobs"
            )
    else:
        cur.close(); db.close()

    return redirect("/jobs")

# ============================================================
#  EVENTS
# ============================================================

'''@app.route("/create_event", methods=["GET", "POST"])
@login_required
def create_event():

    if request.method == "POST":

        ticket_price = request.form.get("ticket_price") or None

        image = request.files.get("image")
        filename = ""
        if image and image.filename != "":
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db  = get_db()
        cur = db.cursor()

        cur.execute("""
            INSERT INTO events (
                user_id, event_title, place, google_map_link,
                event_date, event_day, event_time, duration,
                about_event, ticket_type, ticket_price, total_seats, image
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"],
            request.form["event_title"],
            request.form["place"],
            request.form["google_map_link"],
            request.form["event_date"],
            request.form["event_day"],
            request.form["event_time"],
            request.form["duration"],
            request.form["about_event"],
            request.form["ticket_type"],
            ticket_price,
            request.form["total_seats"],
            filename
        ))
        db.commit()
        cur.close(); db.close()

        return redirect("/events")

    return render_template("create_event.html")'''

@app.route("/create_event", methods=["GET", "POST"])
@login_required
def create_event():

    if request.method == "POST":

        ticket_price = request.form.get("ticket_price") or None
        want_boost   = request.form.get("want_boost") == "yes"
        event_title  = request.form["event_title"].strip()

        image = request.files.get("image")
        filename = ""
        if image and image.filename != "":
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db  = get_db()
        cur = db.cursor(dictionary=True)

        # ── prevent duplicate submission ──────────────────
        cur.execute("""
            SELECT id FROM events
            WHERE user_id = %s
              AND event_title = %s
              AND created_at > NOW() - INTERVAL 30 SECOND
        """, (session["user_id"], event_title))

        if cur.fetchone():
            # already inserted in last 30 seconds — redirect without inserting again
            cur.close(); db.close()
            return redirect("/events")

        # ── insert ────────────────────────────────────────
        cur.execute("""
            INSERT INTO events (
                user_id, event_title, place, google_map_link,
                event_date, event_day, event_time, duration,
                about_event, ticket_type, ticket_price, total_seats, image
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"],
            event_title,
            request.form["place"],
            request.form.get("google_map_link", ""),
            request.form["event_date"],
            request.form.get("event_day", ""),
            request.form.get("event_time", ""),
            request.form.get("duration", ""),
            request.form["about_event"],
            request.form["ticket_type"],
            ticket_price,
            request.form.get("total_seats", 0),
            filename
        ))
        db.commit()
        new_id = cur.lastrowid
        cur.close(); db.close()

        if want_boost:
            return redirect(f"/boost/event/{new_id}")
        return redirect("/events")

    return render_template("create_event.html")



@app.route("/events")
@login_required
def events():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        SELECT events.*, users.username, users.profile_image
        FROM events
        JOIN users ON events.user_id = users.id
        ORDER BY events.event_date ASC
    """)
    event_list = cur.fetchall()

    cur.close(); db.close()
    return render_template("events.html", events=event_list)


# ============================================================
#  ALERTS
# ============================================================

'''@app.route("/alerts", methods=["GET", "POST"])
@login_required
def alerts():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        title       = request.form.get("title")
        description = request.form.get("description")
        alert_type  = request.form.get("alert_type")    # e.g. emergency, news, notice
        location    = request.form.get("location", session.get("location", ""))

        file = request.files.get("image")
        
        filename = None
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        cur.execute("""
            INSERT INTO alerts (user_id, title, description, alert_type, location, image)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (session["user_id"], title, description, alert_type, location, filename))
        db.commit()

        cur.close(); db.close()
        return redirect("/alerts")

    user_location = session.get("location", "")
    cur.execute("""
        SELECT alerts.*, users.username, users.profile_image
        FROM alerts
        JOIN users ON alerts.user_id = users.id
        WHERE alerts.location = %s OR %s = ''
        ORDER BY alerts.created_at DESC
    """, (user_location, user_location))
    alert_list = cur.fetchall()

    for alert in alert_list:
        alert["days_live"] = days_since(alert["created_at"])

    cur.close(); db.close()
    return render_template("alerts.html", alerts=alert_list)'''

@app.route("/alerts", methods=["GET", "POST"])
@login_required
def alerts():

    db  = get_db()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":

        title       = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        alert_type  = request.form.get("alert_type", "notice")
        location    = request.form.get("location", "").strip() or session.get("location", "")

        file = request.files.get("image")
        filename = None
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        try:
            cur.execute("""
                INSERT INTO alerts (user_id, title, description, alert_type, location, image)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session["user_id"], title, description, alert_type, location, filename))
            db.commit()
        except Exception as e:
            print("ALERT INSERT ERROR:", e)   # ← check your terminal for this
            cur.close(); db.close()
            return f"Database error: {e}", 500

        cur.close(); db.close()
        return redirect("/alerts")

    user_location = session.get("location", "")
    cur.execute("""
        SELECT alerts.*, users.username, users.profile_image
        FROM alerts
        JOIN users ON alerts.user_id = users.id
        WHERE (alerts.location = %s OR %s = '')
        ORDER BY alerts.created_at DESC
    """, (user_location, user_location))
    alert_list = cur.fetchall()

    for item in alert_list:
        item["days_live"] = days_since(item["created_at"])

    cur.close(); db.close()
    return render_template("alerts.html", alerts=alert_list)

@app.route("/delete_alert/<int:alert_id>", methods=["POST"])
@login_required
def delete_alert(alert_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "DELETE FROM alerts WHERE id = %s AND user_id = %s",
        (alert_id, session["user_id"])
    )
    db.commit()
    cur.close(); db.close()
    return redirect("/profile")


@app.route("/delete_event/<int:event_id>", methods=["POST"])
@login_required
def delete_event(event_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "DELETE FROM events WHERE id = %s AND user_id = %s",
        (event_id, session["user_id"])
    )
    db.commit()
    cur.close(); db.close()
    return redirect("/profile")

@app.context_processor
def inject_user():
    if "user_id" in session:
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, profile_image, location FROM users WHERE id = %s",
            (session["user_id"],)
        )
        current_user = cur.fetchone()
        cur.close(); db.close()
        return {"current_user": current_user}
    return {"current_user": None}

# ── LIKE (toggle) ─────────────────────────────────────────
@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute(
        "SELECT id FROM likes WHERE user_id=%s AND post_id=%s",
        (session["user_id"], post_id)
    )
    existing = cur.fetchone()

    if existing:
        cur.execute(
            "DELETE FROM likes WHERE user_id=%s AND post_id=%s",
            (session["user_id"], post_id)
        )
        liked = False
    else:
        cur.execute(
            "INSERT INTO likes (user_id, post_id) VALUES (%s,%s)",
            (session["user_id"], post_id)
        )
        liked = True

    db.commit()

    cur.execute("SELECT COUNT(*) AS total FROM likes WHERE post_id=%s", (post_id,))
    total = cur.fetchone()["total"]
    cur.close(); db.close()

    return jsonify({"success": True, "liked": liked, "likes_count": total})

# ── ADD COMMENT ───────────────────────────────────────────
@app.route("/comment/<int:post_id>", methods=["POST"])
@login_required
def add_comment(post_id):
    db   = get_db()
    cur  = db.cursor()
    data = request.get_json()
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"success": False, "error": "Empty comment"})

    cur.execute(
        "INSERT INTO comments (post_id, user_id, text) VALUES (%s,%s,%s)",
        (post_id, session["user_id"], text)
    )
    db.commit()
    cur.close(); db.close()
    return jsonify({"success": True})

# ── GET COMMENTS ──────────────────────────────────────────
@app.route("/get_comments/<int:post_id>")
@login_required
def get_comments(post_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT comments.text, users.username, comments.created_at
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = %s
        ORDER BY comments.created_at ASC
    """, (post_id,))
    comments = cur.fetchall()
    # convert datetime to string so jsonify works
    for c in comments:
        c["created_at"] = str(c["created_at"])
    cur.close(); db.close()
    return jsonify(comments)

@app.route("/messages")
@login_required
def messages():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    uid = session["user_id"]

    # get all users except self for new conversation picker
    cur.execute("""
        SELECT id, username, profile_image
        FROM users
        WHERE id != %s
        ORDER BY username ASC
    """, (uid,))
    all_users = cur.fetchall()

    # get conversations — find latest message per unique contact
    cur.execute("""
        SELECT
            u.id, u.username, u.profile_image,
            m.content  AS last_message,
            m.created_at AS last_time,
            m.sender_id,
            (SELECT COUNT(*) FROM messages m2
             WHERE m2.sender_id = u.id
               AND m2.receiver_id = %s
               AND m2.is_read = FALSE) AS unread_count
        FROM users u
        JOIN messages m ON (
            m.id = (
                SELECT id FROM messages m3
                WHERE (m3.sender_id = %s AND m3.receiver_id = u.id)
                   OR (m3.sender_id = u.id AND m3.receiver_id = %s)
                ORDER BY m3.created_at DESC
                LIMIT 1
            )
        )
        WHERE u.id != %s
        ORDER BY m.created_at DESC
    """, (uid, uid, uid, uid))
    conversations = cur.fetchall()

    cur.close(); db.close()
    return render_template("messages.html",
                           conversations=conversations,
                           all_users=all_users,
                           other=None,
                           msgs=[])

@app.route("/messages/<int:other_id>")
@login_required
def conversation(other_id):
    db  = get_db()
    cur = db.cursor(dictionary=True)
    uid = session["user_id"]

    cur.execute(
        "SELECT id, username, profile_image FROM users WHERE id = %s",
        (other_id,)
    )
    other = cur.fetchone()
    if not other:
        cur.close(); db.close()
        return redirect("/messages")

    # mark incoming messages as read
    cur.execute("""
        UPDATE messages SET is_read = TRUE
        WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
    """, (other_id, uid))
    db.commit()

    # full conversation history
    cur.execute("""
        SELECT messages.*, users.username, users.profile_image
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE (sender_id = %s AND receiver_id = %s)
           OR (sender_id = %s AND receiver_id = %s)
        ORDER BY created_at ASC
    """, (uid, other_id, other_id, uid))
    msgs = cur.fetchall()

    # all users for the picker (needed here too)
    cur.execute("""
        SELECT id, username, profile_image
        FROM users WHERE id != %s ORDER BY username ASC
    """, (uid,))
    all_users = cur.fetchall()

    # conversations for sidebar
    cur.execute("""
        SELECT
            u.id, u.username, u.profile_image,
            m.content AS last_message,
            m.created_at AS last_time,
            m.sender_id,
            (SELECT COUNT(*) FROM messages m2
             WHERE m2.sender_id = u.id
               AND m2.receiver_id = %s
               AND m2.is_read = FALSE) AS unread_count
        FROM users u
        JOIN messages m ON (
            m.id = (
                SELECT id FROM messages m3
                WHERE (m3.sender_id = %s AND m3.receiver_id = u.id)
                   OR (m3.sender_id = u.id AND m3.receiver_id = %s)
                ORDER BY m3.created_at DESC
                LIMIT 1
            )
        )
        WHERE u.id != %s
        ORDER BY m.created_at DESC
    """, (uid, uid, uid, uid))
    conversations = cur.fetchall()

    cur.close(); db.close()
    return render_template("messages.html",
                           other=other,
                           msgs=msgs,
                           all_users=all_users,
                           conversations=conversations)

@app.route("/messages/send", methods=["POST"])
@login_required
def send_message():
    data        = request.get_json()
    receiver_id = data.get("receiver_id")
    content     = (data.get("content") or "").strip()

    if not receiver_id or not content:
        return jsonify({"success": False, "error": "Missing fields"})

    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        INSERT INTO messages (sender_id, receiver_id, content)
        VALUES (%s, %s, %s)
    """, (session["user_id"], receiver_id, content))
    db.commit()
    msg_id = cur.lastrowid

    cur.execute("""
        SELECT messages.*, users.username, users.profile_image
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.id = %s
    """, (msg_id,))
    msg = cur.fetchone()
    msg["created_at"] = str(msg["created_at"])

    cur.close(); db.close()
    return jsonify({"success": True, "message": msg})

@app.route("/messages/poll/<int:other_id>")
@login_required
def poll_messages(other_id):
    since = request.args.get("since", "1970-01-01 00:00:00")
    db    = get_db()
    cur   = db.cursor(dictionary=True)
    uid   = session["user_id"]

    cur.execute("""
        SELECT messages.*, users.username, users.profile_image
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE ((sender_id = %s AND receiver_id = %s)
            OR (sender_id = %s AND receiver_id = %s))
          AND messages.created_at > %s
        ORDER BY created_at ASC
    """, (uid, other_id, other_id, uid, since))
    new_msgs = cur.fetchall()

    for m in new_msgs:
        m["created_at"] = str(m["created_at"])

    cur.execute("""
        UPDATE messages SET is_read = TRUE
        WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
    """, (other_id, uid))
    db.commit()

    cur.close(); db.close()
    return jsonify(new_msgs)

@app.route("/messages/unread_count")
@login_required
def unread_count():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT COUNT(*) AS total FROM messages
        WHERE receiver_id = %s AND is_read = FALSE
    """, (session["user_id"],))
    count = cur.fetchone()["total"]
    cur.close(); db.close()
    return jsonify({"count": count})

@app.route("/boost/<post_type>/<int:post_id>")
@login_required
def boost_page(post_type, post_id):

    # only allow these three types
    allowed_types = ["job", "service", "event"]
    if post_type not in allowed_types:
        return redirect("/feed")

    db  = get_db()
    cur = db.cursor(dictionary=True)

    table_map = {
        "job":     "jobs",
        "service": "services",
        "event":   "events"
    }
    table = table_map[post_type]

    cur.execute(
        f"SELECT * FROM {table} WHERE id = %s AND user_id = %s",
        (post_id, session["user_id"])
    )
    post = cur.fetchone()
    cur.close(); db.close()

    if not post:
        return redirect("/feed")

    return render_template("boost.html",
                           post=post,
                           post_type=post_type,
                           post_id=post_id,
                           plans=BOOST_PLANS,
                           razorpay_key=RAZORPAY_KEY_ID)

@app.route("/boost/create_order", methods=["POST"])
@login_required
def create_boost_order():
    data      = request.get_json()
    post_id   = data.get("post_id")
    post_type = data.get("post_type")
    plan_key  = data.get("plan")

    # only these three allowed
    if post_type not in ["job", "service", "event"]:
        return jsonify({"success": False, "error": "Boost not available for this post type"})

    plan = BOOST_PLANS.get(plan_key)
    if not plan:
        return jsonify({"success": False, "error": "Invalid plan"})

    order = razorpay_client.order.create({
        "amount":          plan["amount"],
        "currency":        "INR",
        "payment_capture": 1,
        "notes": {
            "post_id":   str(post_id),
            "post_type": post_type,
            "plan":      plan_key,
            "user_id":   str(session["user_id"])
        }
    })

    db  = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO boost_payments
            (user_id, post_id, post_type, plan, amount, duration_days,
             razorpay_order_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,'pending')
    """, (
        session["user_id"], post_id, post_type, plan_key,
        plan["amount"] / 100, plan["days"], order["id"]
    ))
    db.commit()
    cur.close(); db.close()

    return jsonify({
        "success":  True,
        "order_id": order["id"],
        "amount":   plan["amount"],
        "currency": "INR",
        "plan":     plan
    })

@app.route("/boost/verify", methods=["POST"])
@login_required
def verify_boost_payment():
    data = request.get_json()

    razorpay_order_id   = data.get("razorpay_order_id")
    razorpay_payment_id = data.get("razorpay_payment_id")
    razorpay_signature  = data.get("razorpay_signature")

    msg      = f"{razorpay_order_id}|{razorpay_payment_id}"
    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        msg.encode(),
        hashlib.sha256
    ).hexdigest()

    if expected != razorpay_signature:
        return jsonify({"success": False, "error": "Invalid signature"})

    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM boost_payments
        WHERE razorpay_order_id = %s AND user_id = %s
    """, (razorpay_order_id, session["user_id"]))
    payment = cur.fetchone()

    if not payment:
        cur.close(); db.close()
        return jsonify({"success": False, "error": "Payment not found"})

    from datetime import datetime, timedelta
    now     = datetime.now()
    ends_at = now + timedelta(days=payment["duration_days"])

    cur.execute("""
        UPDATE boost_payments
        SET status = 'paid',
            razorpay_payment_id = %s,
            boost_starts_at = %s,
            boost_expires_at = %s
        WHERE id = %s
    """, (razorpay_payment_id, now, ends_at, payment["id"]))

    # only jobs, services, events
    table_map = {
        "job":     "jobs",
        "service": "services",
        "event":   "events"
    }
    table = table_map.get(payment["post_type"])
    if table:
        cur.execute(f"""
            UPDATE {table}
            SET is_featured = TRUE, boost_expires_at = %s
            WHERE id = %s
        """, (ends_at, payment["post_id"]))

    db.commit()
    cur.close(); db.close()

    return jsonify({"success": True, "ends_at": str(ends_at)})

@app.route("/boost/my_boosts")
@login_required
def my_boosts():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM boost_payments
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session["user_id"],))
    boosts = cur.fetchall()
    cur.close(); db.close()
    return render_template("my_boosts.html", boosts=boosts)


@app.route("/report_post", methods=["POST"])
@login_required
def report_post():
    data      = request.get_json()
    post_id   = data.get("post_id")
    post_type = data.get("post_type")
    reason    = data.get("reason", "").strip()

    if not post_id or not post_type or not reason:
        return jsonify({"success": False, "error": "Missing fields"})

    db  = get_db()
    cur = db.cursor(dictionary=True)

    # check already reported
    cur.execute("""
        SELECT id FROM post_reports
        WHERE reporter_id = %s AND post_id = %s AND post_type = %s
    """, (session["user_id"], post_id, post_type))

    if cur.fetchone():
        cur.close(); db.close()
        return jsonify({"success": False, "error": "Already reported"})

    # insert report
    cur.execute("""
        INSERT INTO post_reports (reporter_id, post_id, post_type, reason)
        VALUES (%s, %s, %s, %s)
    """, (session["user_id"], post_id, post_type, reason))

    # if reason is scam — increment scam count on post owner
    if reason in ["Scam, fraud or spam", "False information"]:
        # get post owner
        table_map = {
            "post": "posts", "job": "jobs", "service": "services",
            "event": "events", "alert": "alerts"
        }
        table = table_map.get(post_type)
        if table:
            cur.execute(f"SELECT user_id FROM {table} WHERE id = %s", (post_id,))
            row = cur.fetchone()
            if row:
                owner_id = row["user_id"]
                cur.execute("""
                    UPDATE users
                    SET scam_reports = scam_reports + 1,
                        is_scam_flagged = CASE WHEN scam_reports + 1 >= 3 THEN TRUE ELSE FALSE END
                    WHERE id = %s
                """, (owner_id,))

    # inside report_post(), after UPDATE users SET scam_reports...
    if row:
        owner_id = row["user_id"]
        cur.execute("""
            UPDATE users
            SET scam_reports = scam_reports + 1,
                is_scam_flagged = CASE
                    WHEN scam_reports + 1 >= 3 THEN TRUE
                    ELSE FALSE
                END
            WHERE id = %s
        """, (owner_id,))

        # notify the reported user
        create_notification(
            user_id=owner_id,
            type_="report",
            title="Your Post Was Reported",
            body=f"One of your posts was reported for: {reason}. Please review our community guidelines.",
            link="/profile"
        )

        # extra warning if now flagged
        cur.execute("SELECT scam_reports FROM users WHERE id = %s", (owner_id,))
        updated = cur.fetchone()
        if updated and updated["scam_reports"] >= 3:
            create_notification(
                user_id=owner_id,
                type_="warning",
                title="⚠️ Scam Warning Issued",
                body="Your account has received 3+ scam reports. A warning badge has been added to your posts. Contact support to appeal.",
                link="/legal/community"
            )

    db.commit()
    cur.close(); db.close()
    return jsonify({"success": True})

# ── LEGAL PAGES ───────────────────────────────────────

@app.route("/legal")
def legal():
    return redirect("/legal/privacy")

@app.route("/legal/<section>")
def legal_page(section):
    valid = ["privacy", "terms", "community", "disclaimer", "copyright", "contact"]
    if section not in valid:
        return redirect("/legal/privacy")
    titles = {
        "privacy":    "Privacy Policy",
        "terms":      "Terms & Conditions",
        "community":  "Community Guidelines",
        "disclaimer": "Disclaimer",
        "copyright":  "Copyright Notice",
        "contact":    "Contact Us"
    }
    return render_template("legal.html",
                           section=section,
                           page_title=titles[section])


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("search.html", q="", results=[])

    db  = get_db()
    cur = db.cursor(dictionary=True)
    like = f"%{q}%"

    # jobs
    cur.execute("""
        SELECT id, job_title AS title, organization_name AS subtitle,
               job_description AS body, 'job' AS type, created_at
        FROM jobs
        WHERE job_title LIKE %s OR organization_name LIKE %s OR job_description LIKE %s
        ORDER BY is_featured DESC, created_at DESC LIMIT 10
    """, (like, like, like))
    jobs = cur.fetchall()

    # services
    cur.execute("""
        SELECT id, COALESCE(company_name, shop_name, 'Business') AS title,
               COALESCE(service_type, shop_type, category) AS subtitle,
               COALESCE(service_description, shop_description, bio, content) AS body,
               'service' AS type, created_at
        FROM services
        WHERE company_name LIKE %s OR shop_name LIKE %s
           OR service_type LIKE %s OR service_description LIKE %s
        ORDER BY is_featured DESC, created_at DESC LIMIT 10
    """, (like, like, like, like))
    services = cur.fetchall()

    # events
    cur.execute("""
        SELECT id, event_title AS title, place AS subtitle,
               about_event AS body, 'event' AS type, created_at
        FROM events
        WHERE event_title LIKE %s OR about_event LIKE %s OR place LIKE %s
        ORDER BY event_date ASC LIMIT 10
    """, (like, like, like))
    events = cur.fetchall()

    # alerts
    cur.execute("""
        SELECT id, title, alert_type AS subtitle,
               description AS body, 'alert' AS type, created_at
        FROM alerts
        WHERE title LIKE %s OR description LIKE %s
        ORDER BY created_at DESC LIMIT 10
    """, (like, like))
    alerts = cur.fetchall()

    # posts
    cur.execute("""
        SELECT id, content AS title, type AS subtitle,
               content AS body, 'post' AS type, created_at
        FROM posts
        WHERE content LIKE %s
        ORDER BY created_at DESC LIMIT 10
    """, (like,))
    posts = cur.fetchall()

    results = jobs + services + events + alerts + posts
    results.sort(key=lambda x: x["created_at"], reverse=True)

    cur.close(); db.close()
    return render_template("search.html", q=q, results=results)


import secrets

# store reset tokens {token: {user_id, expires_at}}
reset_tokens = {}

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db  = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, username FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close(); db.close()

        if user:
            token = secrets.token_urlsafe(32)
            reset_tokens[token] = {
                "user_id":    user["id"],
                "expires_at": datetime.now() + timedelta(hours=1)
            }
            reset_url = f"http://localhost:5000/reset_password/{token}"
            try:
                msg = Message(
                    subject="Reset your Ampibians password",
                    recipients=[email],
                    html=f"""
                    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;
                                padding:32px;background:#1a1917;border-radius:12px;">
                        <h2 style="color:#e8622a;">Ampibians</h2>
                        <p style="color:#f0ece4;margin:16px 0;">
                            Hi {user['username']}, click below to reset your password.
                            This link expires in 1 hour.
                        </p>
                        <a href="{reset_url}"
                           style="display:inline-block;background:#e8622a;color:white;
                                  padding:12px 24px;text-decoration:none;font-weight:700;
                                  border-radius:6px;margin:16px 0;">
                            Reset Password
                        </a>
                        <p style="color:#7a756c;font-size:13px;">
                            If you didn't request this, ignore this email.
                        </p>
                    </div>
                    """
                )
                mail.send(msg)
            except Exception as e:
                print("[RESET EMAIL ERROR]", e)

        # always show same message (security — don't reveal if email exists)
        return render_template("forgot_password.html",
                               message="If that email is registered, a reset link has been sent.")

    return render_template("forgot_password.html", message=None)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = reset_tokens.get(token)

    if not record or datetime.now() > record["expires_at"]:
        return render_template("reset_password.html",
                               error="This link has expired or is invalid.", token=token)

    if request.method == "POST":
        password  = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if len(password) < 8:
            return render_template("reset_password.html",
                                   error="Password must be at least 8 characters.", token=token)
        if password != password2:
            return render_template("reset_password.html",
                                   error="Passwords do not match.", token=token)

        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE users SET password = %s WHERE id = %s",
            (generate_password_hash(password), record["user_id"])
        )
        db.commit()
        cur.close(); db.close()

        reset_tokens.pop(token, None)
        return redirect("/?reset=1")

    return render_template("reset_password.html", error=None, token=token)

# ═══════════════════════════════════════════════════════
# NOTIFICATION HELPER
# ═══════════════════════════════════════════════════════

def create_notification(user_id, type_, title, body, link=""):
    """Insert a notification row and send an email."""
    try:
        db  = get_db()
        cur = db.cursor(dictionary=True)

        # insert in-app notification
        cur.execute("""
            INSERT INTO notifications (user_id, type, title, body, link)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, type_, title, body, link))
        db.commit()

        # get user email + name for the email
        cur.execute("SELECT email, username FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close(); db.close()

        if user:
            send_notification_email(
                to_email = user["email"],
                to_name  = user["username"],
                title    = title,
                body     = body,
                link     = link
            )

    except Exception as e:
        print("[NOTIF ERROR]", e)


def send_notification_email(to_email, to_name, title, body, link=""):
    """Send a styled HTML notification email."""
    try:
        link_html = ""
        if link:
            full_link = f"http://localhost:5000{link}"
            link_html = f"""
            <a href="{full_link}"
               style="display:inline-block;margin-top:16px;
                      background:#e8622a;color:white;padding:10px 22px;
                      text-decoration:none;font-weight:700;border-radius:6px;">
                View on Ampibians →
            </a>"""

        msg = Message(
            subject   = f"Ampibians: {title}",
            recipients= [to_email],
            html      = f"""
            <div style="font-family:'DM Sans',sans-serif;max-width:520px;
                        margin:0 auto;background:#1a1917;border-radius:12px;
                        overflow:hidden;">

                <!-- Header -->
                <div style="background:#e8622a;padding:20px 28px;
                            display:flex;align-items:center;gap:10px;">
                    <div style="font-family:monospace;font-size:20px;
                                font-weight:800;color:white;">
                        Ampibians
                    </div>
                </div>

                <!-- Body -->
                <div style="padding:28px;">
                    <p style="color:#f0ece4;font-size:15px;margin-bottom:6px;">
                        Hi <strong>{to_name}</strong>,
                    </p>
                    <h2 style="color:#e8622a;font-size:20px;
                               font-weight:700;margin:12px 0 8px;">
                        {title}
                    </h2>
                    <p style="color:#c0bbb2;font-size:14px;line-height:1.7;">
                        {body}
                    </p>
                    {link_html}
                </div>

                <!-- Footer -->
                <div style="padding:16px 28px;border-top:1px solid #2e2c29;">
                    <p style="color:#7a756c;font-size:12px;margin:0;">
                        You're receiving this because you have an Ampibians account.<br>
                        © 2026 Ampibians · Chennai, Tamil Nadu, India
                    </p>
                </div>
            </div>
            """
        )
        mail.send(msg)
    except Exception as e:
        print("[EMAIL ERROR]", e)


# ═══════════════════════════════════════════════════════
# NOTIFICATION ROUTES
# ═══════════════════════════════════════════════════════

@app.route("/notifications")
@login_required
def notifications():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    uid = session["user_id"]

    cur.execute("""
        SELECT * FROM notifications
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 60
    """, (uid,))
    notifs = cur.fetchall()

    # count unread before marking read
    unread_count = sum(1 for n in notifs if not n["is_read"])

    # mark all as read
    cur.execute("""
        UPDATE notifications
        SET is_read = TRUE
        WHERE user_id = %s AND is_read = FALSE
    """, (uid,))
    db.commit()
    cur.close(); db.close()

    return render_template("notifications.html",
                           notifications=notifs,
                           unread_count=unread_count,
                           now_date=date.today().strftime('%d %b %Y'))


@app.route("/notifications/unread_count")
@login_required
def notifications_unread_count():
    db  = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT COUNT(*) AS total FROM notifications
        WHERE user_id = %s AND is_read = FALSE
    """, (session["user_id"],))
    count = cur.fetchone()["total"]
    cur.close(); db.close()
    return jsonify({"count": count})


@app.route("/notifications/mark_read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute("""
        UPDATE notifications SET is_read = TRUE
        WHERE id = %s AND user_id = %s
    """, (notif_id, session["user_id"]))
    db.commit()
    cur.close(); db.close()
    return jsonify({"success": True})


@app.route("/notifications/mark_all_read", methods=["POST"])
@login_required
def mark_all_read():
    db  = get_db()
    cur = db.cursor()
    cur.execute("""
        UPDATE notifications SET is_read = TRUE
        WHERE user_id = %s
    """, (session["user_id"],))
    db.commit()
    cur.close(); db.close()
    return redirect("/notifications")

ADMIN_EMAILS = [
    "official13301330@gmail.com"
]

def admin_required(f):

    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):

        print("SESSION:", session)

        if "user_id" not in session:
            return redirect("/")

        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute(
            "SELECT email FROM users WHERE id = %s",
            (session["user_id"],)
        )

        user = cur.fetchone()

        cur.close()
        db.close()

        print("DB USER:", user)

        if not user:
            return "Access denied - no user", 403

        user_email = str(user["email"]).strip().lower()

        print("USER EMAIL:", user_email)
        print("ADMIN EMAILS:", ADMIN_EMAILS)

        if user_email not in [x.lower() for x in ADMIN_EMAILS]:
            return "Access denied - not admin", 403

        return f(*args, **kwargs)

    return decorated

@app.route("/admin")
@admin_required
def admin_dashboard():
    db  = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT COUNT(*) AS total FROM users")
    user_count = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM jobs")
    job_count = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM services")
    svc_count = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM post_reports")
    report_count = cur.fetchone()["total"]

    cur.execute("""
        SELECT users.id, users.username, users.email, users.scam_reports,
               users.is_scam_flagged, users.created_at,
               COUNT(post_reports.id) AS report_count
        FROM users
        LEFT JOIN post_reports ON post_reports.reporter_id = users.id
        GROUP BY users.id
        ORDER BY users.scam_reports DESC, users.created_at DESC
        LIMIT 50
    """)
    users = cur.fetchall()

    cur.execute("""
        SELECT post_reports.*, users.username AS reporter
        FROM post_reports
        JOIN users ON post_reports.reporter_id = users.id
        ORDER BY post_reports.created_at DESC
        LIMIT 30
    """)
    reports = cur.fetchall()

    cur.close(); db.close()
    return render_template("admin.html",
                           user_count=user_count,
                           job_count=job_count,
                           svc_count=svc_count,
                           report_count=report_count,
                           users=users,
                           reports=reports)


@app.route("/admin/ban/<int:user_id>", methods=["POST"])
@admin_required
def admin_ban_user(user_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE users SET is_scam_flagged = TRUE, scam_reports = 99 WHERE id = %s",
        (user_id,)
    )
    db.commit()
    cur.close(); db.close()
    return redirect("/admin")


@app.route("/admin/unban/<int:user_id>", methods=["POST"])
@admin_required
def admin_unban_user(user_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE users SET is_scam_flagged = FALSE, scam_reports = 0 WHERE id = %s",
        (user_id,)
    )
    db.commit()
    cur.close(); db.close()
    return redirect("/admin")


@app.route("/admin/delete_post/<post_type>/<int:post_id>", methods=["POST"])
@admin_required
def admin_delete_post(post_type, post_id):
    db  = get_db()
    cur = db.cursor()
    table_map = {
        "post": "posts", "job": "jobs", "service": "services",
        "event": "events", "alert": "alerts"
    }
    table = table_map.get(post_type)
    if table:
        cur.execute(f"DELETE FROM {table} WHERE id = %s", (post_id,))
        db.commit()
    cur.close(); db.close()
    return redirect("/admin")


@app.route('/save_post', methods=['POST'])
def save_post():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    data = request.get_json()
    post_id = data.get('post_id')
    post_type = data.get('post_type', 'post')
    user_id = session['user_id']

    db = get_db()
    cur = db.cursor(dictionary=True)

    if not post_id or post_type not in ['post', 'job', 'service', 'event', 'alert']:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    # ✅ Create cursor from your DB connection
    cur = db.cursor(dictionary=True)   # use db.cursor() if not mysql.connector

    # Check if already saved — note %s for MySQL
    cur.execute(
        'SELECT id FROM saved_posts WHERE user_id = %s AND post_id = %s AND post_type = %s',
        (user_id, post_id, post_type)
    )
    existing = cur.fetchone()

    if existing:
        # Remove save (toggle off)
        cur.execute(
            'DELETE FROM saved_posts WHERE user_id = %s AND post_id = %s AND post_type = %s',
            (user_id, post_id, post_type)
        )
        db.commit()
        cur.close()
        return jsonify({'success': True, 'saved': False})
    else:
        # Add save
        cur.execute(
            'INSERT INTO saved_posts (user_id, post_id, post_type, saved_at) VALUES (%s, %s, %s, %s)',
            (user_id, post_id, post_type, datetime.now())
        )
        db.commit()
        cur.close()
        return jsonify({'success': True, 'saved': True})

# ============================================================
#  RUN
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
