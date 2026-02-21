import os
import json
import hmac
import hashlib
import shutil
import threading
import bcrypt
import mysql.connector
from datetime import datetime, UTC, timedelta
from flask import Flask, request, session, jsonify, send_from_directory
from functools import wraps
from flask_cors import CORS

# ===============================
# GLOBAL SECURITY SETTINGS
# ===============================

MAX_ATTEMPTS = 5
LOCK_TIME_SECONDS = 60
FAILED_IP_ATTEMPTS = {}
LEDGER_FILE = "secure_logs_chain.json"

# ===============================
# IMMUTABLE LEDGER
# ===============================

class ImmutableAuditLedger:
    def __init__(self, file_path=LEDGER_FILE, secret_key="LEDGER_HMAC_SECRET"):
        self.file_path = file_path
        self.secret_key = secret_key.encode()
        self.lock = threading.Lock()

        if not os.path.exists(self.file_path):
            self._create_genesis_block()

    def _calculate_hash(self, index, timestamp, data, previous_hash):
        data_string = json.dumps(data, sort_keys=True)
        raw = f"{index}{timestamp}{data_string}{previous_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _sign_hash(self, block_hash):
        return hmac.new(self.secret_key, block_hash.encode(), hashlib.sha256).hexdigest()

    def _create_genesis_block(self):
        ts = datetime.now(UTC).isoformat(timespec="seconds")
        data = {"event": "GENESIS", "msg": "Audit chain initialized"}
        block_hash = self._calculate_hash(0, ts, data, "0")

        block = {
            "index": 0,
            "timestamp": ts,
            "data": data,
            "previous_hash": "0",
            "hash": block_hash,
            "signature": self._sign_hash(block_hash)
        }

        self._atomic_save([block])

    def load_chain(self):
        try:
            with open(self.file_path, "r") as f:
                return json.load(f)
        except:
            return []

    def _atomic_save(self, chain):
        temp = f"{self.file_path}.tmp"
        with open(temp, "w") as f:
            json.dump(chain, f, indent=4)
        shutil.move(temp, self.file_path)

    def verify_chain(self):
        chain = self.load_chain()
        if not chain:
            return False, "Chain empty"

        for i in range(len(chain)):
            b = chain[i]

            recalculated = self._calculate_hash(
                b["index"], b["timestamp"], b["data"], b["previous_hash"]
            )

            if b["hash"] != recalculated:
                return False, f"Hash mismatch at block {i}"

            if b["signature"] != self._sign_hash(b["hash"]):
                return False, f"Signature mismatch at block {i}"

            if i > 0 and b["previous_hash"] != chain[i - 1]["hash"]:
                return False, f"Broken link at block {i}"

        return True, "Valid"

    def add_block(self, event_type, payload):
        with self.lock:
            chain = self.load_chain()
            if not chain:
                self._create_genesis_block()
                chain = self.load_chain()

            prev = chain[-1]
            ts = datetime.now(UTC).isoformat(timespec="seconds")
            data = {"event_type": event_type, "payload": payload}
            new_index = prev["index"] + 1
            h = self._calculate_hash(new_index, ts, data, prev["hash"])

            new_block = {
                "index": new_index,
                "timestamp": ts,
                "data": data,
                "previous_hash": prev["hash"],
                "hash": h,
                "signature": self._sign_hash(h)
            }

            chain.append(new_block)
            self._atomic_save(chain)

# ===============================
# FLASK APP
# ===============================

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_RANDOM_SECRET"
app.permanent_session_lifetime = timedelta(hours=8)
CORS(app, supports_credentials=True)

ledger = ImmutableAuditLedger()
valid, msg = ledger.verify_chain()
if not valid:
    print(f"[FATAL] Ledger corrupted: {msg}")
    exit()
else:
    print("[OK] Ledger integrity verified.")

# ===============================
# DATABASE
# ===============================

db_config = {
    "host": "localhost",
    "user": "root",
    "password": "madhan123",
    "database": "network_monitor"
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# ===============================
# LOGGING FUNCTIONS
# ===============================

def create_login_log(user, ip, fingerprint, status):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        now_naive = datetime.now(UTC).replace(tzinfo=None)

        cursor.execute("""
            INSERT INTO access_logs
            (username, ip_address, login_time, status, fingerprint)
            VALUES (%s, %s, %s, %s, %s)
        """, (user, ip, now_naive, status, fingerprint))

        conn.commit()
        log_id = cursor.lastrowid
        cursor.close()
        return log_id

    except Exception as e:
        print(f"[ERROR] Login Log Failed: {e}")
        return None
    finally:
        if conn and conn.is_connected():
            conn.close()

def close_login_session(log_id):
    conn = None
    try:
        if not log_id:
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT login_time FROM access_logs WHERE id=%s", (log_id,))
        row = cursor.fetchone()

        if row and row[0]:
            login_time = row[0]
            if login_time.tzinfo:
                login_time = login_time.replace(tzinfo=None)

            logout_time = datetime.now(UTC).replace(tzinfo=None)
            duration = int((logout_time - login_time).total_seconds())

            cursor.execute("""
                UPDATE access_logs
                SET logout_time=%s,
                    duration_seconds=%s,
                    status='CLOSED'
                WHERE id=%s
            """, (logout_time, duration, log_id))

            conn.commit()

        cursor.close()

    except Exception as e:
        print(f"[ERROR] Logout Update Failed: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()

# ===============================
# SECURITY HELPERS
# ===============================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def get_fingerprint():
    raw = f"{request.remote_addr}{request.headers.get('User-Agent')}"
    return hashlib.sha256(raw.encode()).hexdigest()

# ===============================
# SERVE FRONTEND
# ===============================

@app.route("/")
def serve_client():
    return send_from_directory(".", "client.html")

# ===============================
# LOGIN (WEB + FINGERPRINT + CARD)
# ===============================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    staff_id = data.get("staff_id")
    card_id = data.get("card_id")
    username = data.get("username")
    password = data.get("password")

    auth_method = None

    if staff_id:
        login_user = staff_id
        ip = "N/A (Fingerprint)"
        fingerprint = hashlib.sha256(f"fp_device_{staff_id}".encode()).hexdigest()
        auth_method = "FINGERPRINT"

    elif card_id:
        login_user = card_id
        ip = "N/A (ID_CARD)"
        fingerprint = hashlib.sha256(f"card_device_{card_id}".encode()).hexdigest()
        auth_method = "ID_CARD"

    else:
        login_user = username
        ip = request.remote_addr
        fingerprint = get_fingerprint()
        auth_method = "WEB"

    now = datetime.now(UTC)

    if auth_method == "WEB":
        if ip in FAILED_IP_ATTEMPTS:
            info = FAILED_IP_ATTEMPTS[ip]
            if info.get("lock_until") and now < info["lock_until"]:
                create_login_log(login_user, ip, fingerprint, "BLOCKED")
                return jsonify({"error": "IP temporarily blocked"}), 403

        attempts = FAILED_IP_ATTEMPTS.get(ip, {}).get("count", 0)
    else:
        attempts = 0

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM admins WHERE username=%s", (login_user,))
        row = cursor.fetchone()

        if not row:
            create_login_log(login_user, ip, fingerprint, "FAILED")
            return jsonify({"error": "Access Denied"}), 401

        stored_hash = row[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()

        auth_success = False

        if auth_method in ["FINGERPRINT", "ID_CARD"]:
            auth_success = True
        elif password and bcrypt.checkpw(password.encode(), stored_hash):
            auth_success = True

        if auth_success:
            if auth_method == "WEB":
                FAILED_IP_ATTEMPTS.pop(ip, None)

            log_id = create_login_log(login_user, ip, fingerprint, "OPEN")

            session.permanent = True
            session["admin_user"] = login_user
            session["fingerprint"] = fingerprint
            session["log_id"] = log_id

            ledger.add_block("LOGIN", {
                "user": login_user,
                "method": auth_method
            })

            return jsonify({"message": "Access Granted"})

        if auth_method == "WEB":
            attempts += 1
            if attempts >= MAX_ATTEMPTS:
                FAILED_IP_ATTEMPTS[ip] = {
                    "count": attempts,
                    "lock_until": now + timedelta(seconds=LOCK_TIME_SECONDS)
                }
                create_login_log(login_user, ip, fingerprint, "BLOCKED")
                return jsonify({"error": "IP temporarily blocked"}), 403

            FAILED_IP_ATTEMPTS[ip] = {"count": attempts, "lock_until": None}

        create_login_log(login_user, ip, fingerprint, "FAILED")
        return jsonify({"error": "Access Denied"}), 401

    except Exception as e:
        print("Auth Error:", e)
        create_login_log(login_user, ip, fingerprint, "ERROR")
        return jsonify({"error": "Server error"}), 500
    finally:
        cursor.close()
        conn.close()

# ===============================
# LOGOUT
# ===============================

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = session.get("admin_user")
    ip = request.remote_addr
    log_id = session.get("log_id")

    if log_id:
        close_login_session(log_id)

    ledger.add_block("LOGOUT", {
        "user": user,
        "ip": ip
    })

    session.clear()
    return jsonify({"message": "Logged out"})

# ===============================
# PROTECTED API
# ===============================

@app.route("/api/monitor", methods=["GET"])
@login_required
def api_monitor():
    current_fp = get_fingerprint()
    sess_fp = session.get("fingerprint")
    log_id = session.get("log_id")

    if "fp_device_" not in str(sess_fp) and "card_device_" not in str(sess_fp):
        if sess_fp != current_fp:
            session.clear()
            return jsonify({"error": "Session violation detected"}), 403

    if log_id:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT login_time FROM access_logs WHERE id=%s", (log_id,))
            row = cursor.fetchone()

            if row and row[0]:
                login_time = row[0]
                if login_time.tzinfo:
                    login_time = login_time.replace(tzinfo=None)

                now = datetime.now(UTC).replace(tzinfo=None)
                duration = (now - login_time).total_seconds()

                if duration > 8 * 60 * 60:
                    close_login_session(log_id)
                    session.clear()
                    return jsonify({"error": "Session expired (8 hours limit)"}), 401

            cursor.close()
            conn.close()

        except Exception as e:
            print("Session expiry check failed:", e)

    valid, msg = ledger.verify_chain()

    if not valid:
        return jsonify({
            "ledger_integrity": {
                "status": "CORRUPTED",
                "details": msg
            }
        }), 500

    return jsonify({
        "infrastructure": { "HR_Printer": { "status": True } },
        "ledger_integrity": {"status": "SECURE"},
        "server_time": datetime.now(UTC).isoformat(timespec="seconds")
    })

# ===============================
# ATTACK SIMULATION
# ===============================

@app.route("/simulate/corrupt", methods=["POST"])
def simulate_corruption():
    try:
        if os.path.exists(LEDGER_FILE):
            with open(LEDGER_FILE, "r") as f:
                data = json.load(f)

            if len(data) > 0:
                data[0]["data"]["msg"] = "HAX0R WAS HERE"

                with open(LEDGER_FILE, "w") as f:
                    json.dump(data, f, indent=4)

                return jsonify({"message": "Ledger Corrupted Successfully"}), 200

        return jsonify({"error": "Ledger not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/session_log", methods=["POST"])
@login_required
def session_log():
    data = request.get_json()
    ledger.add_block("SESSION_EVENT", data)
    return jsonify({"message": "Logged"})

# ===============================
# ADMIN LOGIN REPORTS
# ===============================

@app.route("/api/admin/success_logins", methods=["GET"])
@login_required
def admin_success_logins():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, username, ip_address, login_time, logout_time, duration_seconds, status
            FROM access_logs
            WHERE username = 'admin'
            AND status IN ('OPEN', 'CLOSED')
            ORDER BY login_time DESC
        """)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/failed_logins", methods=["GET"])
@login_required
def admin_failed_logins():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, username, ip_address, login_time, status
            FROM access_logs
            WHERE username = 'admin'
            AND status = 'FAILED'
            ORDER BY login_time DESC
        """)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ===============================
# RUN
# ===============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)