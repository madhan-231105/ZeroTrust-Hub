import os
import json
import hmac
import hashlib
import shutil
import threading
import bcrypt
import mysql.connector
from datetime import datetime, UTC, timedelta
from flask import Flask, request, session, jsonify
from functools import wraps

# ===============================
# GLOBAL SECURITY SETTINGS
# ===============================

MAX_ATTEMPTS = 5
LOCK_TIME_SECONDS = 60

FAILED_IP_ATTEMPTS = {}

# ===============================
# 1. IMMUTABLE LEDGER
# ===============================

class ImmutableAuditLedger:
    def __init__(self, file_path="secure_logs_chain.json", secret_key="LEDGER_HMAC_SECRET"):
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
        h = self._calculate_hash(0, ts, data, "0")

        block = {
            "index": 0,
            "timestamp": ts,
            "data": data,
            "previous_hash": "0",
            "hash": h,
            "signature": self._sign_hash(h)
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
app.secret_key = "highly_secure_and_random_key"

ledger = ImmutableAuditLedger()

valid, msg = ledger.verify_chain()
if not valid:
    print(f"[FATAL] Ledger corrupted at startup: {msg}")
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
# LOGGING
# ===============================

def log_event(user, ip, status, event_type, msg):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, ip_address, login_time, status)
            VALUES (%s, %s, %s, %s)
        """, (user, ip, datetime.now(UTC), status))
        conn.commit()
        cursor.close()
        conn.close()
    except:
        pass

    ledger.add_block(event_type, {"user": user, "ip": ip, "msg": msg})

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
# LOGIN ROUTE
# ===============================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")
    ip = request.remote_addr

    attempts = FAILED_IP_ATTEMPTS.get(ip, 0)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM admins WHERE username=%s", (username,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            return jsonify({"error": "Access Denied"}), 401

        stored_hash = row[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()

        # SUCCESS
        if bcrypt.checkpw(password.encode(), stored_hash):
            FAILED_IP_ATTEMPTS.pop(ip, None)

            session["admin_user"] = username
            session["fingerprint"] = get_fingerprint()

            log_event(username, ip, "SUCCESS", "LOGIN", "Login successful")
            return jsonify({"message": "Access Granted"})

        # FAILURE
        attempts += 1
        FAILED_IP_ATTEMPTS[ip] = attempts

        if attempts >= MAX_ATTEMPTS:
            # Reset immediately so future valid login works
            FAILED_IP_ATTEMPTS.pop(ip, None)

            return jsonify({
                "error": "IP temporarily blocked"
            }), 403

        log_event(username, ip, "FAILED", "AUTH_FAILURE", "Invalid password")
        return jsonify({"error": "Access Denied"}), 401

    except Exception as e:
        print("Auth Error:", e)
        return jsonify({"error": "Server error"}), 500

# ===============================
# PROTECTED API
# ===============================

@app.route("/api/monitor", methods=["GET"])
@login_required
def api_monitor():

    if session.get("fingerprint") != get_fingerprint():
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
        "ledger_integrity": {
            "status": "SECURE"
        }
    })

# ===============================
# RUN
# ===============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)