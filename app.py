
from flask import Flask, request, redirect, render_template, url_for, make_response, jsonify
from urllib.parse import urlparse
import string, random, re, os, logging, time, hmac, hashlib, base64
from datetime import datetime, timezone
from supabase import create_client, Client

# ======================================================
# ENV VARS (Vercel → Project Settings → Environment Variables)
#   - SUPABASE_URL
#   - SUPABASE_KEY   (service_role disarankan)
# ======================================================
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Set SUPABASE_URL dan SUPABASE_KEY di Environment Variables.")

TABLE_USERS = "users"
TABLE_LINKS = "links"

# Cookie token ditandatangani dengan SUPABASE_KEY (tidak ada secret tambahan)
TOKEN_COOKIE = "auth"
TOKEN_AGE_SECONDS = 7 * 24 * 3600  # 7 hari

app = Flask(__name__, static_folder='static', static_url_path='/static')
logging.basicConfig(level=logging.INFO)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def now_utc():
    return datetime.now(timezone.utc)

def ensure_scheme(u: str) -> str:
    if not u: return u
    p = urlparse(u)
    if not p.scheme:
        return "https://" + u
    return u

def is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return bool(p.netloc) and "." in p.netloc
    except:
        return False

def is_valid_code(code: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_-]{3,20}$', code or ""))

def random_code(n: int = 6) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(n))

# ========== Token (HMAC dengan SUPABASE_KEY) ==========
def sign_token(user_id: int, username: str, exp_ts: int) -> str:
    msg = f"{user_id}|{username}|{exp_ts}".encode()
    sig = hmac.new(SUPABASE_KEY.encode(), msg, hashlib.sha256).digest()
    b64sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{user_id}|{username}|{exp_ts}|{b64sig}"

def parse_token(token: str):
    try:
        parts = token.split("|")
        if len(parts) != 4:
            return None
        user_id = int(parts[0])
        username = parts[1]
        exp_ts = int(parts[2])
        sig = parts[3]

        msg = f"{user_id}|{username}|{exp_ts}".encode()
        expected = base64.urlsafe_b64encode(hmac.new(SUPABASE_KEY.encode(), msg, hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(sig, expected):
            return None
        if exp_ts < int(time.time()):
            return None
        return {"id": user_id, "username": username}
    except Exception:
        return None

def current_user():
    tok = request.cookies.get(TOKEN_COOKIE)
    return parse_token(tok) if tok else None

def require_login():
    u = current_user()
    if u is None:
        return redirect(url_for("login", next=request.path))
    return None

def set_auth_cookie(resp, user_id, username):
    exp = int(time.time()) + TOKEN_AGE_SECONDS
    tok = sign_token(user_id, username, exp)
    resp.set_cookie(
        TOKEN_COOKIE, tok, max_age=TOKEN_AGE_SECONDS,
        httponly=True, samesite="Lax", secure=True
    )
    return resp

def clear_auth_cookie(resp):
    resp.set_cookie(TOKEN_COOKIE, "", max_age=0)
    return resp

# ========== Supabase helpers ==========
def code_exists(code: str) -> bool:
    try:
        r = supabase.table(TABLE_LINKS).select("id").eq("short_code", code).limit(1).execute()
        return bool(r.data)
    except Exception as e:
        logging.error(f"code_exists error: {e}")
        return True

def create_link(owner_id: int, short_code: str, target_url: str):
    payload = {
        "owner_id": owner_id,
        "short_code": short_code,
        "target_url": target_url,
        "created_at": now_utc().isoformat()
    }
    supabase.table(TABLE_LINKS).insert(payload).execute()

def list_links(owner_id: int):
    r = supabase.table(TABLE_LINKS).select("*").eq("owner_id", owner_id).order("created_at", desc=True).execute()
    return r.data or []

def delete_link(owner_id: int, short_code: str):
    supabase.table(TABLE_LINKS).delete().eq("owner_id", owner_id).eq("short_code", short_code).execute()

# ========== Routes ==========
@app.route("/", methods=["GET"])
def index():
    user = current_user()
    return render_template("index.html", user=user, result=None, error=None)

@app.route("/shorten", methods=["POST"])
def shorten():
    guard = require_login()
    if guard is not None:
        return guard
    user = current_user()
    url = ensure_scheme((request.form.get("url") or "").strip())
    custom = (request.form.get("custom_code") or "").strip()
    if not is_valid_url(url):
        return render_template("index.html", user=user, error="URL tidak valid", result=None)
    if custom:
        if not is_valid_code(custom):
            return render_template("index.html", user=user, error="Kode kustom 3–20 (huruf/angka/_/-).", result=None)
        if code_exists(custom):
            return render_template("index.html", user=user, error="Kode sudah dipakai.", result=None)
        chosen = custom
    else:
        for _ in range(10):
            c = random_code(6)
            if not code_exists(c):
                chosen = c
                break
        else:
            return render_template("index.html", user=user, error="Gagal membuat kode unik.", result=None)
    try:
        create_link(user["id"], chosen, url)
        base = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or "localhost"
        short_url = f"https://{base}/{chosen}"
        return render_template("index.html", user=user, result=short_url, error=None)
    except Exception as e:
        logging.exception("shorten error")
        return render_template("index.html", user=user, error=f"Gagal menyimpan: {e}", result=None)

@app.route("/dashboard", methods=["GET"])
def dashboard():
    guard = require_login()
    if guard is not None:
        return guard
    user = current_user()
    try:
        rows = list_links(user["id"])
        base = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or "localhost"
        for r in rows:
            r["short_url"] = f"https://{base}/{r['short_code']}"
        return render_template("dashboard.html", user=user, links=rows, error=None, success=None)
    except Exception as e:
        logging.exception("dashboard error")
        return render_template("dashboard.html", user=user, links=[], error=str(e), success=None)

@app.route("/delete", methods=["POST"])
def delete():
    guard = require_login()
    if guard is not None:
        return guard
    user = current_user()
    code = (request.form.get("code") or "").strip()
    if not code:
        return redirect(url_for("dashboard"))
    try:
        delete_link(user["id"], code)
        return redirect(url_for("dashboard"))
    except Exception as e:
        logging.exception("delete error")
        return redirect(url_for("dashboard"))

# ========== Auth (tanpa hash; password disimpan plaintext) ==========
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None, next=request.args.get("next", "/"))
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    next_url = request.form.get("next") or "/"
    if not username or not password:
        return render_template("login.html", error="Isi username & password", next=next_url)
    try:
        r = supabase.table(TABLE_USERS).select("id, username, password").eq("username", username).limit(1).execute()
        if not r.data or (r.data[0].get("password") or "") != password:
            return render_template("login.html", error="Username atau password salah", next=next_url)
        row = r.data[0]
        resp = make_response(redirect(next_url))
        return set_auth_cookie(resp, row["id"], row["username"])
    except Exception as e:
        logging.exception("login error")
        return render_template("login.html", error=f"Gagal login: {e}", next=next_url)

@app.route("/logout", methods=["POST"])
def logout():
    resp = make_response(redirect(url_for("login")))
    return clear_auth_cookie(resp)

# ========== Redirect ==========
@app.route("/<short_code>", methods=["GET"])
def go(short_code: str):
    try:
        r = supabase.table(TABLE_LINKS).select("target_url").eq("short_code", short_code).limit(1).execute()
        if not r.data:
            return render_template("404.html"), 404
        return redirect(r.data[0]["target_url"], code=302)
    except Exception as e:
        logging.exception("redirect error")
        return render_template("404.html"), 404

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404
