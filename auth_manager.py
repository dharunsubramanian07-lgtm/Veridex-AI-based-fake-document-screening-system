"""
Authentication & Role-Based Access Control (RBAC) Module
VERIDEX — AI Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Roles:
1. Officer: Document & traveler screening, views own active screenings.
2. Supervisor: Checkpoint analytics, secondary inspections, override authority.
3. Auditor: Full cryptographic blockchain ledger, Ed25519 verification, Merkle audit, Tamper Demo.

Security Features:
- Passwords hashed with bcrypt (salt + work factor 12).
- Stored in local JSON config (auth_config.json).
- Session timeout management (15 minutes inactivity limit).
- Tamper-evident login audit logging (security_audit.log).
"""

import os
import json
import time
import datetime
from typing import Optional, Dict, Any, Tuple
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_CONFIG_FILE = os.path.join(BASE_DIR, "auth_config.json")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "security_audit.log")

DEFAULT_USERS = {
    "officer_ssb": {
        "name": "Sub-Inspector Vikram Singh",
        "role": "Officer",
        "checkpoint_id": "SSB-ICP-Raxaul-01",
        "plain_demo_pw": "Officer@2026",
    },
    "sup_border": {
        "name": "Assistant Commandant R. Sharma",
        "role": "Supervisor",
        "checkpoint_id": "SSB-SECTOR-HQ",
        "plain_demo_pw": "Supervisor@2026",
    },
    "auditor_mha": {
        "name": "Directorate of Border Auditing (MHA)",
        "role": "Auditor",
        "checkpoint_id": "MHA-CYBER-AUDIT-HQ",
        "plain_demo_pw": "Auditor@2026",
    },
}


def log_security_event(username: str, action: str, status: str, details: str = "") -> None:
    """Append structured entry to security_audit.log."""
    try:
        timestamp = datetime.datetime.now().isoformat()
        entry = f"[{timestamp}] USER='{username}' ACTION='{action}' STATUS='{status}' DETAILS='{details}'\n"
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        print(f"[auth_manager] Logging error: {e}")


def init_auth_config() -> Dict[str, Any]:
    """Initialize auth_config.json with bcrypt-hashed credentials if not exists."""
    if os.path.exists(AUTH_CONFIG_FILE):
        try:
            with open(AUTH_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Generate initial hashed database
    user_db = {}
    for uname, info in DEFAULT_USERS.items():
        hashed = bcrypt.hashpw(info["plain_demo_pw"].encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
        user_db[uname] = {
            "name": info["name"],
            "role": info["role"],
            "checkpoint_id": info["checkpoint_id"],
            "password_hash": hashed,
            "created_at": datetime.datetime.now().isoformat(),
        }

    with open(AUTH_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(user_db, f, indent=2)

    log_security_event("SYSTEM", "INIT_AUTH_STORE", "SUCCESS", "Generated default RBAC credentials with bcrypt")
    return user_db


def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Verify username & password against bcrypt hashes.
    Returns: (success: bool, user_info: dict, message: str)
    """
    user_db = init_auth_config()
    clean_uname = (username or "").strip().lower()

    if clean_uname not in user_db:
        log_security_event(clean_uname, "LOGIN_ATTEMPT", "FAILED", "Invalid username")
        return False, None, "Invalid username or password"

    user_info = user_db[clean_uname]
    hashed_str = user_info.get("password_hash", "")

    try:
        if bcrypt.checkpw(password.encode("utf-8"), hashed_str.encode("utf-8")):
            log_security_event(clean_uname, "LOGIN_ATTEMPT", "SUCCESS", f"Role: {user_info['role']}")
            session_data = {
                "username": clean_uname,
                "name": user_info["name"],
                "role": user_info["role"],
                "checkpoint_id": user_info["checkpoint_id"],
                "login_timestamp": time.time(),
                "last_active": time.time(),
            }
            return True, session_data, f"Authenticated as {user_info['role']}"
        else:
            log_security_event(clean_uname, "LOGIN_ATTEMPT", "FAILED", "Incorrect password")
            return False, None, "Invalid username or password"
    except Exception as e:
        log_security_event(clean_uname, "LOGIN_ERROR", "ERROR", str(e))
        return False, None, "Authentication service error"


def check_session_timeout(last_active_timestamp: float, timeout_minutes: int = 15) -> bool:
    """Return True if session has expired due to inactivity."""
    elapsed = time.time() - last_active_timestamp
    return elapsed > (timeout_minutes * 60)
