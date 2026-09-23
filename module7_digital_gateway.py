"""
Module 7 (Extension): VERIDEX Digital Document Gateway (DigiLocker Mimic)
VERIDEX — AI-Powered Fake Identity & Document Screening System
SIH 2026 Hackathon Prototype | Ministry of Home Affairs / SSB Theme

CRITICAL LEGAL & SIMULATION DISCLAIMER:
-----------------------------------------
This module is a strictly offline Hackathon simulation / demonstration engine.
DO NOT connect to real DigiLocker, UIDAI, Aadhaar OTP, or government production services.
DO NOT collect, store, or transmit real citizen Aadhaar credentials or real OTPs.
All credentials, tokens, OTPs, and digital certificates generated here are synthetic
simulation objects designed exclusively for offline prototype evaluation.
"""

import os
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "digilocker_mimic")
USERS_FILE = os.path.join(VAULT_DIR, "users.json")
METADATA_DIR = os.path.join(VAULT_DIR, "metadata")

# ---------------------------------------------------------------------------
# Demo Credentials & Simulation Constants
# ---------------------------------------------------------------------------
DEMO_CONFIG = {
    "default_mobile": "9999999999",
    "default_aadhaar": "123456789012",
    "default_otp": "123456",
    "default_pin": "1234",
    "disclaimer": "VERIDEX Digital Document Gateway — Prototype / Simulation only. No real DigiLocker or Aadhaar credentials are collected.",
}

# Catalog of Simulated DigiLocker Citizens & Issued Documents
CITIZEN_CATALOG = {
    "VX001": {
        "user_id": "VX001",
        "full_name": "Sriram Mamundi",
        "phone": "+91 99999 99999",
        "mobile_raw": "9999999999",
        "aadhaar_raw": "123456789012",
        "email": "sriram.mamundi@demo.gov.in",
        "verified_status": "ISSUER_VERIFIED",
        "verification_level": "LEVEL_3_KYC (DigiLocker Gold)",
        "account_created": "2021-03-15T10:00:00Z",
        "avatar_icon": "👨‍💼",
        "issued_documents": [
            {
                "doc_id": "DOC-AADH-001",
                "doc_type": "aadhaar",
                "doc_name": "Aadhaar Card",
                "doc_number": "8416 1590 3267",
                "masked_number": "XXXX XXXX 3267",
                "issuer": "UIDAI / Government of India",
                "issued_on": "2018-05-12",
                "expiry": "LIFELONG",
                "sample_image": "sample_docs/aadhar1.jpg",
                "recommended_person": "sample_docs/person1.jpg",
                "digital_signature": "ED25519-UIDAI-SIG-VALID",
                "metadata_file": "metadata/VX001.json",
                "status": "VERIFIED_ACTIVE",
                "category": "National Identity",
                "icon": "🪪",
            },
            {
                "doc_id": "DOC-DL-001",
                "doc_type": "driving_license",
                "doc_name": "Driving Licence (Smart Card)",
                "doc_number": "TN42 20220004426",
                "masked_number": "TN42 2022*****26",
                "issuer": "MoRTH / Tamil Nadu Transport Dept",
                "issued_on": "2022-10-07",
                "expiry": "2042-10-06",
                "sample_image": "sample_docs/license.jpg",
                "recommended_person": "sample_docs/person1.jpg",
                "digital_signature": "ED25519-MORTH-SIG-VALID",
                "metadata_file": "metadata/VX001.json",
                "status": "VERIFIED_ACTIVE",
                "category": "Transport & Driving",
                "icon": "🚗",
            },
            {
                "doc_id": "DOC-PASS-001",
                "doc_type": "passport",
                "doc_name": "Indian Regular Passport",
                "doc_number": "P8923412",
                "masked_number": "P89****2",
                "issuer": "Ministry of External Affairs (CPV Division)",
                "issued_on": "2019-08-20",
                "expiry": "2029-08-19",
                "sample_image": "sample_docs/passport_girish.jpg",
                "recommended_person": "sample_docs/person1.jpg",
                "digital_signature": "ED25519-MEA-SIG-VALID",
                "metadata_file": "metadata/VX001.json",
                "status": "VERIFIED_ACTIVE",
                "category": "Travel Document",
                "icon": "🛂",
            },
        ],
        "uploaded_documents": [
            {
                "doc_id": "DOC-MY-001",
                "doc_name": "PAN Card (e-PAN)",
                "doc_number": "ABCDE1234F",
                "category": "Self Uploaded",
                "uploaded_on": "2023-01-10",
                "status": "SELF_CERTIFIED",
            }
        ],
    },
    "VX002": {
        "user_id": "VX002",
        "full_name": "Anna Eriksson",
        "phone": "+46 70 123 4567",
        "mobile_raw": "7012345678",
        "aadhaar_raw": "987654321098",
        "email": "anna.eriksson@demo.gov.se",
        "verified_status": "ISSUER_VERIFIED",
        "verification_level": "LEVEL_3_KYC (International)",
        "account_created": "2020-01-20T08:30:00Z",
        "avatar_icon": "👩‍💼",
        "issued_documents": [
            {
                "doc_id": "DOC-PASS-002",
                "doc_type": "passport",
                "doc_name": "International Passport",
                "doc_number": "D23145890",
                "masked_number": "D231****0",
                "issuer": "Utrikesdepartementet / Passport Authority (UTO)",
                "issued_on": "2002-04-15",
                "expiry": "2012-04-14",
                "sample_image": "sample_docs/passport2.jpg",
                "recommended_person": "sample_docs/person2.jpg",
                "digital_signature": "ED25519-UTO-SIG-VALID",
                "metadata_file": "metadata/VX002.json",
                "status": "VERIFIED_ACTIVE",
                "category": "International Travel",
                "icon": "🛂",
            },
            {
                "doc_id": "DOC-VISA-001",
                "doc_type": "visa",
                "doc_name": "Republic of India Visa / Tourist Permit",
                "doc_number": "VIND982341",
                "masked_number": "VIND****41",
                "issuer": "Bureau of Immigration / MHA India",
                "issued_on": "2024-01-15",
                "expiry": "2025-01-14",
                "sample_image": "sample_docs/visa_traveler.jpg",
                "recommended_person": "sample_docs/person2.jpg",
                "digital_signature": "ED25519-BOI-SIG-VALID",
                "metadata_file": "metadata/VX002.json",
                "status": "VERIFIED_ACTIVE",
                "category": "Entry Clearance",
                "icon": "🎫",
            },
        ],
        "uploaded_documents": [],
    },
    "VX003": {
        "user_id": "VX003",
        "full_name": "Arun Kumar",
        "phone": "+91 98765 43210",
        "mobile_raw": "9876543210",
        "aadhaar_raw": "548291037461",
        "email": "arun.kumar@demo.gov.in",
        "verified_status": "ISSUER_VERIFIED",
        "verification_level": "LEVEL_3_KYC (DigiLocker Gold)",
        "account_created": "2022-06-11T12:00:00Z",
        "avatar_icon": "👨‍🎓",
        "issued_documents": [
            {
                "doc_id": "DOC-AADH-003",
                "doc_type": "aadhaar",
                "doc_name": "Aadhaar Card",
                "doc_number": "5482 9103 7461",
                "masked_number": "XXXX XXXX 7461",
                "issuer": "UIDAI / Government of India",
                "issued_on": "2019-11-20",
                "expiry": "LIFELONG",
                "sample_image": "sample_docs/aadhaar_arun.jpg",
                "recommended_person": "sample_docs/person3.jpg",
                "digital_signature": "ED25519-UIDAI-SIG-VALID",
                "metadata_file": "metadata/VX001.json",
                "status": "VERIFIED_ACTIVE",
                "category": "National Identity",
                "icon": "🪪",
            },
            {
                "doc_id": "DOC-DL-003",
                "doc_type": "driving_license",
                "doc_name": "Driving Licence (Smart Card)",
                "doc_number": "TN38 20210009871",
                "masked_number": "TN38 2021*****71",
                "issuer": "MoRTH / Tamil Nadu Transport Dept",
                "issued_on": "2021-04-18",
                "expiry": "2041-04-17",
                "sample_image": "sample_docs/license_akash.jpg",
                "recommended_person": "sample_docs/person3.jpg",
                "digital_signature": "ED25519-MORTH-SIG-VALID",
                "metadata_file": "metadata/VX001.json",
                "status": "VERIFIED_ACTIVE",
                "category": "Transport & Driving",
                "icon": "🚗",
            },
        ],
        "uploaded_documents": [],
    },
}

# In-memory activity log store
ACTIVITY_LOGS: List[Dict[str, Any]] = [
    {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "GATEWAY_INITIALIZED",
        "user_id": "SYSTEM",
        "details": "VERIDEX Digital Document Gateway simulation engine initialized.",
        "security_hash": hashlib.sha256(b"GATEWAY_INIT").hexdigest()[:16],
    }
]


# ---------------------------------------------------------------------------
# Authentication & Verification Engine
# ---------------------------------------------------------------------------

def verify_gateway_login(identifier: str, auth_type: str = "mobile") -> Tuple[bool, str, Optional[str]]:
    """
    Validate user identifier (Mobile or Aadhaar/VID) against simulated demo registry.
    Returns: (is_valid, message, matched_user_id)
    """
    clean_id = "".join(filter(str.isdigit, str(identifier).strip()))
    if not clean_id:
        return False, "Please enter a valid mobile number or Aadhaar ID.", None

    # Check for direct matches in citizen catalog
    for u_id, citizen in CITIZEN_CATALOG.items():
        if auth_type == "mobile" and (clean_id == citizen["mobile_raw"] or clean_id == citizen["phone"].replace(" ", "").replace("+91", "")):
            return True, f"Authentication request accepted for {citizen['full_name']}.", u_id
        if auth_type == "aadhaar" and clean_id == citizen["aadhaar_raw"]:
            return True, f"Authentication request accepted for {citizen['full_name']}.", u_id

    # Fallback to default demo user VX001 for any 10-digit mobile or 12-digit Aadhaar in simulation mode
    if auth_type == "mobile" and len(clean_id) == 10:
        return True, "Demo mobile accepted. OTP dispatched.", "VX001"
    if auth_type == "aadhaar" and len(clean_id) in (12, 16):
        return True, "Demo Aadhaar/VID accepted. OTP dispatched.", "VX001"

    if auth_type == "mobile":
        return False, "Please enter a 10-digit mobile number (Demo: 9999999999).", None
    else:
        return False, "Please enter a 12-digit Aadhaar number (Demo: 123456789012).", None


def verify_gateway_otp(entered_otp: str) -> Tuple[bool, str]:
    """
    Validate 6-digit OTP (Demo accepts '123456' or any 6-digit number in flexible demo mode).
    """
    clean_otp = str(entered_otp).strip()
    if len(clean_otp) != 6 or not clean_otp.isdigit():
        return False, "Please enter a valid 6-digit OTP."
    if clean_otp == DEMO_CONFIG["default_otp"] or clean_otp in ("123456", "000000", "999999"):
        return True, "OTP verified successfully. Please enter your 4-digit Security PIN."
    # Accept any 6-digit numeric OTP for ease of evaluation
    return True, "OTP verified successfully. Please enter your 4-digit Security PIN."


def get_initials(name: str) -> str:
    """Extract 2-letter uppercase initials for avatar badge."""
    parts = str(name).strip().split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    elif len(parts) == 1 and len(parts[0]) >= 2:
        return parts[0][:2].upper()
    elif len(parts) == 1 and len(parts[0]) == 1:
        return (parts[0] + parts[0]).upper()
    return "DS"


def get_masked_name(name: str) -> str:
    """Format name into authentic DigiLocker masked format like S*****m M."""
    parts = str(name).strip().split()
    if len(parts) >= 2:
        first = parts[0]
        last = parts[-1]
        if len(first) > 2:
            masked_first = first[0] + ("*" * (len(first) - 2)) + first[-1]
        else:
            masked_first = first[0] + "***"
        return f"{masked_first} {last[0]}"
    elif len(parts) == 1:
        n = parts[0]
        if len(n) > 2:
            return n[0] + ("*" * (len(n) - 2)) + n[-1]
        return n + "***"
    return "S*****m M"


def verify_gateway_pin(entered_pin: str) -> Tuple[bool, str]:
    """
    Validate Security PIN (Demo accepts 4 to 6 digit PINs like '1234' or '123456').
    """
    clean_pin = str(entered_pin).strip()
    if len(clean_pin) not in (4, 6) or not clean_pin.isdigit():
        return False, "Please enter a valid 6-digit Security PIN."
    return True, "Security PIN verified. DigiLocker Digital Wallet unlocked."


# ---------------------------------------------------------------------------
# Wallet & Document Access Helpers
# ---------------------------------------------------------------------------

def get_citizen_profile(user_id: str) -> Dict[str, Any]:
    """Retrieve full citizen profile by User ID."""
    return CITIZEN_CATALOG.get(user_id, CITIZEN_CATALOG["VX001"])


def get_citizen_documents(user_id: str) -> List[Dict[str, Any]]:
    """Retrieve list of issued documents for the citizen."""
    citizen = get_citizen_profile(user_id)
    return citizen.get("issued_documents", [])


def get_gateway_document_by_id(user_id: str, doc_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific document from a citizen's issued wallet."""
    docs = get_citizen_documents(user_id)
    for doc in docs:
        if doc.get("doc_id") == doc_id:
            # Attach resolved absolute file path
            rel_path = doc.get("sample_image")
            if rel_path:
                doc["absolute_image_path"] = os.path.join(BASE_DIR, rel_path)
            rec_person = doc.get("recommended_person")
            if rec_person:
                doc["absolute_person_path"] = os.path.join(BASE_DIR, rec_person)
            return doc
    return None


def log_gateway_event(event_type: str, details: str, user_id: str = "VX001", doc_name: str = ""):
    """Record an audit trail event for the gateway session."""
    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "user_id": user_id,
        "doc_name": doc_name,
        "details": details,
        "security_hash": hashlib.sha256(f"{event_type}_{time.time()}_{details}".encode()).hexdigest()[:16],
    }
    ACTIVITY_LOGS.insert(0, event)
    if len(ACTIVITY_LOGS) > 50:
        ACTIVITY_LOGS.pop()


def get_gateway_activity_logs() -> List[Dict[str, Any]]:
    """Get all recorded gateway audit events."""
    return ACTIVITY_LOGS
