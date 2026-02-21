import requests
import json
import time
import os

# CONFIGURATION
BASE_URL = "http://127.0.0.1:5001"
TARGET_USER = "admin"
REAL_PASS = "admin123"
LEDGER_FILE = "secure_logs_chain.json"

def print_header(title):
    print(f"\n{'='*60}\n[TEST] {title}\n{'='*60}")

# ==========================================
# 1. BRUTE FORCE SIMULATION
# ==========================================
def simulate_brute_force():
    print_header("Simulating Brute Force Attack")
    for i in range(6):
        print(f"Attempt {i+1}: Trying password 'wrong_pass_{i}'...")
        payload = {"username": TARGET_USER, "password": f"wrong_pass_{i}"}
        response = requests.post(f"{BASE_URL}/login", json=payload)
        
        if response.status_code == 403:
            print(f"[DEFENSE TRIGGERED] Server blocked IP: {response.json()}")
            return
        elif response.status_code == 401:
            print(f"Server rejected login (401).")
        
    print("[FAIL] Brute force defense did not trigger within 6 attempts.")

# ==========================================
# 2. UNAUTHORIZED ACCESS SIMULATION
# ==========================================
def simulate_unauthorized():
    print_header("Testing Unauthorized Access to Protected Route")
    response = requests.get(f"{BASE_URL}/api/monitor")
    if response.status_code == 401:
        print(f"[DEFENSE SUCCESS] Access denied as expected: {response.json()}")
    else:
        print(f"[FAIL] Accessed protected route without login! Status: {response.status_code}")

# ==========================================
# 3. SESSION HIJACKING (FINGERPRINT MISMATCH)
# ==========================================
def simulate_session_hijack():
    print_header("Simulating Session Hijacking (Fingerprint Change)")
    
    # Step 1: Login as a normal Desktop user
    session = requests.Session()
    headers_desktop = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
    session.headers.update(headers_desktop)
    
    login_res = session.post(f"{BASE_URL}/login", json={"username": TARGET_USER, "password": REAL_PASS})
    
    if login_res.status_code == 200:
        print("Step 1: Successfully logged in with Desktop User-Agent.")
        
        # Step 2: Attempt to use the SAME session/cookie but change the User-Agent (Simulating a stolen cookie on a different device)
        print("Step 2: Attempting to use stolen cookie with a Mobile User-Agent...")
        headers_mobile = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"}
        
        # We use the same session (cookies) but different headers
        hijack_res = session.get(f"{BASE_URL}/api/monitor", headers=headers_mobile)
        
        if hijack_res.status_code == 403:
            print(f"[DEFENSE SUCCESS] Hijack detected! Fingerprint mismatch: {hijack_res.json()}")
        else:
            print(f"[FAIL] Session hijack successful! Fingerprint did not block access.")
    else:
        print("Login failed, cannot test hijack.")

# ==========================================
# 4. BLOCKCHAIN TAMPERING SIMULATION
# ==========================================
def simulate_ledger_tampering():
    print_header("Simulating Manual Ledger Corruption")
    
    if not os.path.exists(LEDGER_FILE):
        print("Ledger file not found. Run a login first.")
        return

    # Step 1: Login to get access
    session = requests.Session()
    session.post(f"{BASE_URL}/login", json={"username": TARGET_USER, "password": REAL_PASS})

    # Step 2: Manually corrupt the blockchain file (change an event type)
    print("Step 1: Manually modifying secure_logs_chain.json to simulate tampering...")
    with open(LEDGER_FILE, "r") as f:
        data = json.load(f)
    
    if len(data) > 1:
        data[1]["data"]["event_type"] = "MALICIOUS_ENTRY" # Tampering with Block 1
        with open(LEDGER_FILE, "w") as f:
            json.dump(data, f)
            
        # Step 3: Check API to see if it detects the corruption
        print("Step 2: Checking API monitor for integrity status...")
        response = session.get(f"{BASE_URL}/api/monitor")
        
        status = response.json().get("ledger_integrity", {})
        if status.get("status") == "CORRUPTED":
            print(f"[DEFENSE SUCCESS] Tampering detected: {status['details']}")
        else:
            print("[FAIL] System did not detect the manual file change!")
    else:
        print("Not enough blocks in chain to simulate tampering. Log in and out a few times.")

# ==========================================
# RUN ALL TESTS
# ==========================================
if __name__ == "__main__":
    print("SECURE-CORE DEFENSE VALIDATION SUITE")
    print("Ensure your Flask server is running on port 5001 before starting.")
    
    simulate_unauthorized()
    simulate_brute_force()
    simulate_session_hijack()
    simulate_ledger_tampering()
    
    print("\nSimulation Complete.")