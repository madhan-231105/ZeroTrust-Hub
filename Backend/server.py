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

# REQUIRED: Terminate session after 8 hours
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
    """Stores the login time of the card or fingerprint"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # FIX 1: Use naive time for MySQL compatibility
        now_naive = datetime.now(UTC).replace(tzinfo=None)

        cursor.execute("""
            INSERT INTO access_logs
            (username, ip_address, login_time, status, fingerprint)
            VALUES (%s, %s, %s, %s, %s)
        """, (user, ip, now_naive, status, fingerprint))

        conn.commit()
        
        # FIX 2: Ensure ID is captured
        log_id = cursor.lastrowid
        print(f"[DEBUG] Log created. Status: {status}, ID: {log_id}")

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
            
            # FIX 3: Timezone aware subtraction fix
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
            print(f"[DEBUG] Session {log_id} closed. Duration: {duration}s")

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
    try:
        return send_from_directory(".", "client.html")
    except:
        return "Client HTML not found", 404

# ===============================
# LOGIN (UPDATED)
# ===============================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    staff_id = data.get("staff_id")
    username = data.get("username")
    # Also support 'card_id' from the ID swipe function
    card_id = data.get("card_id")
    password = data.get("password")
    
    # REQUIRED logic: Distinguish between fingerprint, card, and web auth
    is_fingerprint = bool(staff_id)
    is_card = bool(card_id)
    
    if is_fingerprint:
        # FINGERPRINT LOGIN LOGIC (No IP, uses Staff ID)
        login_user = staff_id
        ip = "N/A (Fingerprint)"
        fingerprint = hashlib.sha256(f"fp_device_{staff_id}".encode()).hexdigest()
    elif is_card:
        # ID CARD LOGIN LOGIC (Uses Card ID)
        login_user = card_id
        # Card swipes come from controllers, but for this demo we capture request IP
        ip = request.remote_addr 
        fingerprint = get_fingerprint()
    else:
        # WEB LOGIN LOGIC
        login_user = username
        ip = request.remote_addr
        fingerprint = get_fingerprint() 

    now = datetime.now(UTC)

    # 1. Check IP Block (Only for non-fingerprint methods)
    if not is_fingerprint:
        if ip in FAILED_IP_ATTEMPTS:
            info = FAILED_IP_ATTEMPTS[ip]
            if info.get("lock_until") and now < info["lock_until"]:
                create_login_log(login_user, ip, fingerprint, "BLOCKED")
                return jsonify({"error": "IP temporarily blocked"}), 403
        attempts = FAILED_IP_ATTEMPTS.get(ip, {}).get("count", 0)
    else:
        attempts = 0 # Fingerprints don't get IP blocked

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM admins WHERE username=%s", (login_user,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        # 2. Check User Existence
        if not row:
            create_login_log(login_user, ip, fingerprint, "FAILED")
            return jsonify({"error": "Access Denied"}), 401

        stored_hash = row[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()

        # 3. Authenticate User
        auth_success = False
        
        if is_fingerprint or is_card:
            # Assumes hardware scanner/reader validated the physical token
            auth_success = True 
        elif password and bcrypt.checkpw(password.encode(), stored_hash):
            auth_success = True

        if auth_success:
            if not is_fingerprint:
                FAILED_IP_ATTEMPTS.pop(ip, None)

            # LOG SUCCESS EVENT (This captures the exact login time)
            log_id = create_login_log(
                login_user,
                ip,
                fingerprint,
                "OPEN"
            )

            # REQUIRED: Set session to be permanent to trigger the 8-hour timeout
            session.permanent = True

            session["admin_user"] = login_user
            session["fingerprint"] = fingerprint
            session["log_id"] = log_id

            ledger.add_block("LOGIN", {
                "user": login_user,
                "ip": ip,
                "method": "FINGERPRINT" if is_fingerprint else ("CARD" if is_card else "WEB")
            })

            return jsonify({"message": "Access Granted"})

        # 4. Failed Login (Wrong Password)
        if not is_fingerprint:
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
# REMOVED @login_required to prevent 401 spam from background checks
def api_monitor():
    
    # Check security only if user is actually logged in
    if "admin_user" in session:
        current_fp = get_fingerprint()
        sess_fp = session.get("fingerprint")
        
        # Bypass strict browser fingerprint checking for hardware-based sessions
        if "fp_device_" not in str(sess_fp) and sess_fp != current_fp:
            session.clear()
            return jsonify({"error": "Session violation detected"}), 403

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
# NEW REPORTING APIS (Added for HTML)
# ===============================

@app.route("/api/admin/success_logins", methods=["GET"])
@login_required
def get_success_logins():
    conn = None
    try:
        conn = get_db_connection()
        # Use dictionary=True so the frontend receives JSON objects
        cursor = conn.cursor(dictionary=True) 
        
        cursor.execute("""
            SELECT id, username, ip_address, login_time, logout_time, status, duration_seconds, fingerprint
            FROM access_logs
            WHERE status IN ('OPEN', 'CLOSED')
            ORDER BY login_time DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()
        cursor.close()
        return jsonify(rows)
    except Exception as e:
        print(f"Error fetching success logins: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route("/api/admin/failed_logins", methods=["GET"])
@login_required
def get_failed_logins():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, username, ip_address, login_time, fingerprint, status
            FROM access_logs
            WHERE status IN ('FAILED', 'BLOCKED', 'ERROR')
            ORDER BY login_time DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()
        cursor.close()
        return jsonify(rows)
    except Exception as e:
        print(f"Error fetching failed logins: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route("/api/session_log", methods=["POST"])
def session_log():
    """Endpoint for frontend to report specific session events"""
    return jsonify({"status": "logged"})

# ===============================
# ATTACK SIMULATION ENDPOINT
# ===============================

@app.route("/simulate/corrupt", methods=["POST"])
def simulate_corruption():
    """Simulates a ledger tampering attack by modifying the file directly"""
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

# ===============================
# RUN
# ===============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)