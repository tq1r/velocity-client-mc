"""
Velocity Client - Custom Authentication Server
================================================
A self-hosted auth backend with admin dashboard for managing
users and license keys.

Usage:
  python server.py              # Start on port 5000 (all interfaces)
  python server.py --port 8080  # Custom port

Deploy to Render:
  Push to GitHub -> New Web Service -> Auto-detected as Python
  Or use the included render.yaml for one-click deploy.

Admin Dashboard: http://<your-host>:5000/admin
Default login: admin / velocity2024  (change on first login)
"""

import sqlite3
import hashlib
import secrets
import string
import time
import json
import os
import argparse
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from flask_cors import CORS

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'velocity-client-secret-key-2024')

# Enable CORS for API routes (needed so the Minecraft mod can connect)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'velocity_auth.db')

# ============================================================
# DATABASE
# ============================================================

def get_db():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    """Create all tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()

    # Admin users (for the dashboard)
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )''')

    # License keys
    c.execute('''CREATE TABLE IF NOT EXISTS license_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        note TEXT DEFAULT '',
        max_uses INTEGER DEFAULT 1,
        current_uses INTEGER DEFAULT 0,
        used_by TEXT DEFAULT '',
        expires_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        is_active INTEGER DEFAULT 1
    )''')

    # Authenticated users (Minecraft players)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        license_key TEXT,
        hwid TEXT DEFAULT '',
        ip TEXT DEFAULT '',
        is_banned INTEGER DEFAULT 0,
        ban_reason TEXT DEFAULT '',
        last_login TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )''')

    # Auth logs
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        ip TEXT DEFAULT '',
        hwid TEXT DEFAULT '',
        success INTEGER DEFAULT 0,
        details TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )''')

    conn.commit()

    # Ensure tq1r admin always exists (update old 'admin' if needed)
    existing = conn.execute("SELECT * FROM admins WHERE username = 'tq1r'").fetchone()
    if not existing:
        # Delete any old default admin
        conn.execute("DELETE FROM admins WHERE username = 'admin'")
        admin_hash = hash_password("velocity2024")
        conn.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                      ("tq1r", admin_hash))
        conn.commit()
        print("[SETUP] Default admin created: tq1r / velocity2024")
    else:
        # Reset password in case it was changed to a broken hash
        admin_hash = hash_password("velocity2024")
        conn.execute("UPDATE admins SET password_hash = ? WHERE username = 'tq1r'",
                      (admin_hash,))
        conn.commit()
        print("[SETUP] Admin password reset: tq1r / velocity2024")

    conn.close()

# ============================================================
# HELPERS
# ============================================================

def hash_password(password, salt=None):
    """Hash a password with a random or provided salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password, stored_hash):
    """Verify a password against its stored hash."""
    if '$' not in stored_hash:
        return False
    try:
        salt, hashed = stored_hash.split('$', 1)
        return hash_password(password, salt) == stored_hash
    except:
        return False

def generate_license_key(prefix="VC"):
    """Generate a random license key."""
    chars = string.ascii_uppercase + string.digits
    segments = ['-'.join(''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4))]
    return f"{prefix}-{segments[0]}"

def require_admin(f):
    """Decorator: require admin login for dashboard routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def log_auth(username, action, ip="", hwid="", success=0, details=""):
    """Log an authentication event."""
    conn = get_db()
    conn.execute(
        "INSERT INTO auth_logs (username, action, ip, hwid, success, details) VALUES (?, ?, ?, ?, ?, ?)",
        (username, action, ip, hwid, success, details)
    )
    conn.commit()
    conn.close()

def get_client_ip():
    """Get the client's IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or 'unknown'

# ============================================================
# ROOT REDIRECT + DEBUG
# ============================================================

@app.route('/')
def index():
    """Redirect root to admin panel."""
    return redirect(url_for('admin_login'))

@app.route('/debug')
def debug():
    """Debug endpoint to check DB state and password verification."""
    try:
        conn = get_db()
        admin = conn.execute("SELECT * FROM admins WHERE username = 'tq1r'").fetchone()
        if not admin:
            conn.close()
            return jsonify({"error": "No admin found"})
        
        stored = admin['password_hash']
        salt, stored_hashed = stored.split('$', 1)
        recomputed = hashlib.sha256((salt + "velocity2024").encode()).hexdigest()
        full_recomputed = f"{salt}:${recomputed}"
        
        result = {
            "stored_full": stored,
            "salt": salt,
            "stored_hash_part": stored_hashed,
            "recomputed_hash_part": recomputed,
            "hash_match": stored_hashed == recomputed,
            "full_match": full_recomputed == stored,
            "verify_fn_result": verify_password("velocity2024", stored),
        }
        conn.close()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# MINECRAFT MOD API (called by the mod)
# ============================================================

@app.route('/api/init', methods=['POST'])
def api_init():
    """Initialize connection - verify the server is reachable."""
    return jsonify({
        "success": True,
        "message": "Velocity Auth Server v1.0",
        "time": datetime.utcnow().isoformat()
    })

@app.route('/api/login', methods=['POST'])
def api_login():
    """Authenticate a user with username and password."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    hwid = data.get('hwid', '')
    ip = get_client_ip()

    if not username or not password:
        return jsonify({"success": False, "message": "Missing username or password"})

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        log_auth(username, "login", ip, hwid, 0, "User not found")
        conn.close()
        return jsonify({"success": False, "message": "Invalid username or password"})

    if user['is_banned']:
        log_auth(username, "login", ip, hwid, 0, f"Banned: {user['ban_reason']}")
        conn.close()
        return jsonify({"success": False, "message": f"Account banned: {user['ban_reason']}"})

    if not verify_password(password, user['password_hash']):
        log_auth(username, "login", ip, hwid, 0, "Wrong password")
        conn.close()
        return jsonify({"success": False, "message": "Invalid username or password"})

    # Check HWID lock (optional - only enforce if HWID is set)
    if user['hwid'] and hwid and user['hwid'] != hwid:
        log_auth(username, "login", ip, hwid, 0, "HWID mismatch")
        conn.close()
        return jsonify({"success": False, "message": "Account locked to another computer. Contact an admin."})

    # Update login info
    conn.execute(
        "UPDATE users SET last_login = datetime('now'), ip = ?, hwid = COALESCE(NULLIF(?, ''), hwid) WHERE id = ?",
        (ip, hwid, user['id'])
    )
    conn.commit()
    conn.close()

    log_auth(username, "login", ip, hwid, 1, "Login successful")
    return jsonify({
        "success": True,
        "message": f"Welcome, {username}!",
        "info": {
            "username": username,
            "subscription": "Velocity Client Premium",
            "expiry": "Permanent",
            "rank": "User"
        }
    })

@app.route('/api/register', methods=['POST'])
def api_register():
    """Register a new user with a license key."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    license_key = data.get('key', '').strip()
    hwid = data.get('hwid', '')
    ip = get_client_ip()

    if not username or not password:
        return jsonify({"success": False, "message": "Missing username or password"})

    if len(username) < 3 or len(username) > 32:
        return jsonify({"success": False, "message": "Username must be 3-32 characters"})

    if len(password) < 4:
        return jsonify({"success": False, "message": "Password must be at least 4 characters"})

    conn = get_db()

    # Check if username exists
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Username already taken"})

    # Validate license key (optional if not provided)
    if license_key:
        key_row = conn.execute(
            "SELECT * FROM license_keys WHERE key = ? AND is_active = 1", (license_key,)
        ).fetchone()

        if not key_row:
            log_auth(username, "register", ip, hwid, 0, f"Invalid key: {license_key}")
            conn.close()
            return jsonify({"success": False, "message": "Invalid license key"})

        # Check if key is expired
        if key_row['expires_at'] and key_row['expires_at'] < datetime.utcnow().isoformat():
            conn.close()
            return jsonify({"success": False, "message": "License key has expired"})

        # Check usage limit
        if key_row['current_uses'] >= key_row['max_uses']:
            conn.close()
            return jsonify({"success": False, "message": "License key has reached its usage limit"})

        # Mark key as used
        conn.execute(
            "UPDATE license_keys SET current_uses = current_uses + 1, used_by = used_by || ? || ',' WHERE id = ?",
            (username + " ", key_row['id'])
        )

    # Create user
    pw_hash = hash_password(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, license_key, hwid, ip) VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, license_key, hwid, ip)
    )
    conn.commit()
    conn.close()

    log_auth(username, "register", ip, hwid, 1, f"Registered with key: {license_key or 'none'}")
    return jsonify({
        "success": True,
        "message": f"Account created: {username}",
        "info": {
            "username": username,
            "subscription": "Velocity Client Premium" if license_key else "Free",
            "expiry": "Permanent",
            "rank": "User"
        }
    })

@app.route('/api/activate', methods=['POST'])
def api_activate_license():
    """Activate a license key directly (no account needed)."""
    data = request.get_json() or {}
    license_key = data.get('key', '').strip()
    hwid = data.get('hwid', '')
    ip = get_client_ip()

    if not license_key:
        return jsonify({"success": False, "message": "Missing license key"})

    conn = get_db()
    key_row = conn.execute(
        "SELECT * FROM license_keys WHERE key = ? AND is_active = 1", (license_key,)
    ).fetchone()

    if not key_row:
        conn.close()
        return jsonify({"success": False, "message": "Invalid license key"})

    if key_row['expires_at'] and key_row['expires_at'] < datetime.utcnow().isoformat():
        conn.close()
        return jsonify({"success": False, "message": "License key has expired"})

    if key_row['current_uses'] >= key_row['max_uses']:
        conn.close()
        return jsonify({"success": False, "message": "License key has reached its usage limit"})

    # Check if this HWID already used this key
    users_with_key = conn.execute(
        "SELECT * FROM users WHERE license_key = ?", (license_key,)
    ).fetchall()

    for u in users_with_key:
        if u['hwid'] == hwid:
            # Already activated on this machine
            log_auth(u['username'], "activate", ip, hwid, 1, "Re-authenticated via license")
            conn.close()
            return jsonify({
                "success": True,
                "message": "License key activated!",
                "info": {
                    "username": u['username'],
                    "subscription": "Velocity Client Premium",
                    "expiry": "Permanent",
                    "rank": "User"
                }
            })

    # Create a new user for this key activation
    username = f"key_{secrets.token_hex(4)}"
    pw_hash = hash_password(secrets.token_hex(32))  # Random password

    conn.execute(
        "INSERT INTO users (username, password_hash, license_key, hwid, ip) VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, license_key, hwid, ip)
    )
    conn.execute(
        "UPDATE license_keys SET current_uses = current_uses + 1 WHERE id = ?",
        (key_row['id'],)
    )
    conn.commit()
    conn.close()

    log_auth(username, "activate", ip, hwid, 1, f"New account via key: {license_key}")
    return jsonify({
        "success": True,
        "message": "License key activated!",
        "info": {
            "username": username,
            "subscription": "Velocity Client Premium",
            "expiry": "Permanent",
            "rank": "User"
        }
    })

# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route('/admin')
@require_admin
def admin_dashboard():
    """Main admin dashboard."""
    conn = get_db()

    stats = {
        'total_users': conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'total_keys': conn.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0],
        'active_keys': conn.execute("SELECT COUNT(*) FROM license_keys WHERE is_active = 1").fetchone()[0],
        'banned_users': conn.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1").fetchone()[0],
        'total_logins': conn.execute("SELECT COUNT(*) FROM auth_logs WHERE action = 'login' AND success = 1").fetchone()[0],
        'today_logins': conn.execute(
            "SELECT COUNT(*) FROM auth_logs WHERE action = 'login' AND success = 1 AND date(created_at) = date('now')"
        ).fetchone()[0],
    }

    recent_logs = conn.execute(
        "SELECT * FROM auth_logs ORDER BY id DESC LIMIT 20"
    ).fetchall()

    recent_users = conn.execute(
        "SELECT * FROM users ORDER BY id DESC LIMIT 10"
    ).fetchall()

    conn.close()
    return render_template('admin.html', stats=stats, logs=recent_logs, users=recent_users)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if admin and verify_password(password, admin['password_hash']):
            session['admin_id'] = admin['id']
            session['admin_user'] = admin['username']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Invalid credentials")

    return render_template('admin_login.html', error=None)

@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.clear()
    return redirect(url_for('admin_login'))

# --- API routes for dashboard AJAX calls ---

@app.route('/admin/api/keys', methods=['GET', 'POST'])
@require_admin
def admin_keys():
    """List or create license keys."""
    conn = get_db()

    if request.method == 'POST':
        data = request.get_json() or {}
        count = min(int(data.get('count', 1)), 100)
        note = data.get('note', '')
        max_uses = max(int(data.get('max_uses', 1)), 1)
        days = data.get('days', '')
        expires_at = None

        if days:
            try:
                exp_date = datetime.utcnow() + timedelta(days=int(days))
                expires_at = exp_date.isoformat()
            except:
                pass

        keys = []
        for _ in range(count):
            key = generate_license_key()
            try:
                conn.execute(
                    "INSERT INTO license_keys (key, note, max_uses, expires_at) VALUES (?, ?, ?, ?)",
                    (key, note, max_uses, expires_at)
                )
                keys.append(key)
            except sqlite3.IntegrityError:
                continue  # Duplicate key (extremely rare)

        conn.commit()
        conn.close()
        return jsonify({"success": True, "keys": keys, "count": len(keys)})

    # GET - list all keys
    keys = conn.execute(
        "SELECT k.*, (SELECT GROUP_CONCAT(u.username, ', ') FROM users u WHERE u.license_key = k.key) as users_used FROM license_keys k ORDER BY k.id DESC"
    ).fetchall()

    conn.close()
    return jsonify([dict(k) for k in keys])

@app.route('/admin/api/keys/<int:key_id>/toggle', methods=['POST'])
@require_admin
def admin_toggle_key(key_id):
    """Enable/disable a license key."""
    conn = get_db()
    conn.execute("UPDATE license_keys SET is_active = 1 - is_active WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/api/keys/<int:key_id>/delete', methods=['POST'])
@require_admin
def admin_delete_key(key_id):
    """Delete a license key."""
    conn = get_db()
    conn.execute("DELETE FROM license_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/api/users', methods=['GET'])
@require_admin
def admin_users():
    """List all users."""
    conn = get_db()
    users = conn.execute("SELECT id, username, license_key, hwid, ip, is_banned, ban_reason, last_login, created_at FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/admin/api/users/<int:user_id>/ban', methods=['POST'])
@require_admin
def admin_ban_user(user_id):
    """Ban or unban a user."""
    conn = get_db()
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    user = conn.execute("SELECT is_banned FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "User not found"})

    new_state = 0 if user['is_banned'] else 1
    if new_state:
        conn.execute("UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ?", (reason, user_id))
    else:
        conn.execute("UPDATE users SET is_banned = 0, ban_reason = '' WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "banned": bool(new_state)})

@app.route('/admin/api/users/<int:user_id>/delete', methods=['POST'])
@require_admin
def admin_delete_user(user_id):
    """Delete a user."""
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/api/users/<int:user_id>/reset_hwid', methods=['POST'])
@require_admin
def admin_reset_hwid(user_id):
    """Reset a user's HWID lock."""
    conn = get_db()
    conn.execute("UPDATE users SET hwid = '' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/api/logs', methods=['GET'])
@require_admin
def admin_logs():
    """Get auth logs."""
    limit = request.args.get('limit', 100, type=int)
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM auth_logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

@app.route('/admin/api/stats')
@require_admin
def admin_stats():
    """Get dashboard statistics."""
    conn = get_db()
    stats = {
        'total_users': conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'total_keys': conn.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0],
        'active_keys': conn.execute("SELECT COUNT(*) FROM license_keys WHERE is_active = 1").fetchone()[0],
        'banned_users': conn.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1").fetchone()[0],
        'today_logins': conn.execute(
            "SELECT COUNT(*) FROM auth_logs WHERE action = 'login' AND success = 1 AND date(created_at) = date('now')"
        ).fetchone()[0],
        'total_logins': conn.execute(
            "SELECT COUNT(*) FROM auth_logs WHERE action = 'login' AND success = 1"
        ).fetchone()[0],
    }
    conn.close()
    return jsonify(stats)

# ============================================================
# CLOUD-READY SETUP
# ============================================================

# Initialize DB on import (needed for cloud platforms like Render)
init_db()

# ============================================================
# MAIN (local dev only)
# ============================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Velocity Client Auth Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    print("=" * 50)
    print("  Velocity Client - Authentication Server v1.1")
    print("=" * 50)

    print(f"[INFO] Database: {DB_PATH}")
    print(f"[INFO] Admin Panel: http://{args.host}:{args.port}/admin")
    print(f"[INFO] API Endpoints:")
    print(f"       POST /api/init       - Health check")
    print(f"       POST /api/login      - User login")
    print(f"       POST /api/register   - User registration")
    print(f"       POST /api/activate   - License key activation")
    print("=" * 50)

    app.run(host=args.host, port=args.port, debug=args.debug)