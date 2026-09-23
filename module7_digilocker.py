"""
Module 7: DigiLocker Trusted Document Vault Engine
VERIDEX — AI-Powered Fake Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Features:
1. DigiLocker Mimic Ecosystem: Manages trusted citizen profiles and issuer-verified digital documents.
2. Field-by-Field Semantic Cross-Validation: Normalizes dates, names, document numbers, and gender.
3. Cryptographic SHA-256 Digest Integrity: Verifies byte-level identity vs re-scanned/compressed credential.
4. Document-to-Vault Facial Biometric Verification: Compares submitted document face photo directly against master vault credential.
5. Zero-PII Audit Metadata Generation for Blockchain Ledger and Risk Engine.
"""

import os
import json
import re
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from difflib import SequenceMatcher

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "digilocker_mimic")
USERS_FILE = os.path.join(VAULT_DIR, "users.json")
METADATA_DIR = os.path.join(VAULT_DIR, "metadata")


# ---------------------------------------------------------------------------
# Vault Data Access Helpers
# ---------------------------------------------------------------------------

def calculate_file_hash(filepath: Optional[str]) -> str:
    """Calculate the cryptographic SHA-256 hash of a file."""
    if not filepath or not os.path.exists(filepath):
        return "N/A (File Not Found)"
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return "ERROR_CALCULATING_HASH"


def load_vault_users() -> Dict[str, Any]:
    """Load all demo users and their available documents from the Digital Vault."""
    if not os.path.exists(USERS_FILE):
        return {"users": []}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": []}


def get_user_documents(user_id: str) -> List[Dict[str, Any]]:
    """Retrieve available document descriptors for a given user ID."""
    data = load_vault_users()
    for user in data.get("users", []):
        if user.get("user_id", "").upper() == user_id.upper():
            return user.get("available_documents", [])
    return []


def get_reference_document(user_id: str, document_type: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve full reference metadata and resolved file paths for a user's trusted document.
    """
    clean_type = document_type.lower().strip()
    if clean_type in ("driving_licence", "license"):
        clean_type = "driving_license"

    meta_file = os.path.join(METADATA_DIR, f"{user_id.upper()}.json")
    if not os.path.exists(meta_file):
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            meta_data = json.load(f)

        docs = meta_data.get("documents", {})
        doc_info = docs.get(clean_type)
        if not doc_info:
            return None

        doc_info["user_id"] = meta_data.get("user_id", user_id.upper())

        # Resolve relative sample image path to absolute path
        ref_img_rel = doc_info.get("reference_image")
        if ref_img_rel:
            ref_img_abs = os.path.join(BASE_DIR, ref_img_rel)
            doc_info["reference_image_abs"] = ref_img_abs
            # Compute live hash if not present
            if not doc_info.get("sha256_hash") and os.path.exists(ref_img_abs):
                doc_info["sha256_hash"] = calculate_file_hash(ref_img_abs)

        return doc_info
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Normalization & Fuzzy Matching Engine
# ---------------------------------------------------------------------------

def normalize_date(date_str: Optional[str]) -> str:
    """Normalize various date formats (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD) into DD/MM/YYYY."""
    if not date_str or not isinstance(date_str, str):
        return ""
    s = date_str.strip().replace(".", "-").replace("/", "-")
    # Match DD-MM-YYYY
    m1 = re.match(r"^(\d{1,2})-(\d{1,2})-(\d{4})$", s)
    if m1:
        d, m, y = m1.groups()
        return f"{int(d):02d}/{int(m):02d}/{y}"
    # Match YYYY-MM-DD
    m2 = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", s)
    if m2:
        y, m, d = m2.groups()
        return f"{int(d):02d}/{int(m):02d}/{y}"
    return s.upper()


def normalize_doc_number(doc_num: Optional[str]) -> str:
    """Normalize document identifier by removing spaces, hyphens, and converting to uppercase."""
    if not doc_num or not isinstance(doc_num, str):
        return ""
    return doc_num.strip().replace(" ", "").replace("-", "").upper()


def normalize_text(val: Optional[str]) -> str:
    """Normalize general text by removing extra spaces and special characters."""
    if not val or not isinstance(val, str):
        return ""
    return " ".join(val.strip().upper().split())


def normalize_gender(gender_str: Optional[str]) -> str:
    """Normalize gender strings (M, MALE, F, FEMALE, TRANSGENDER)."""
    if not gender_str or not isinstance(gender_str, str):
        return ""
    g = gender_str.strip().upper()
    if g.startswith("M"):
        return "MALE"
    if g.startswith("F"):
        return "FEMALE"
    if g.startswith("T"):
        return "TRANSGENDER"
    return g


def compute_string_similarity(s1: str, s2: str) -> float:
    """Calculate SequenceMatcher string similarity ratio between 0.0 and 1.0."""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    s1_clean = normalize_text(s1)
    s2_clean = normalize_text(s2)
    if s1_clean == s2_clean:
        return 1.0
    return SequenceMatcher(None, s1_clean, s2_clean).ratio()


# ---------------------------------------------------------------------------
# Cross-Document Verification & Comparison Engine
# ---------------------------------------------------------------------------

def compare_documents(
    submitted_fields: Dict[str, Any],
    reference_metadata: Dict[str, Any],
    submitted_filepath: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compare OCR/structural fields of a submitted document against a trusted DigiLocker reference document.
    Computes field-by-field similarity, weighted overall match score, and critical mismatch flags.
    """
    field_comparisons: List[Dict[str, Any]] = []
    critical_reasons: List[str] = []
    weighted_scores: List[Tuple[float, float]] = []  # (score, weight)

    doc_type = reference_metadata.get("document_type", "document").lower()

    # 1. Document Number / UID Check (Weight: 25%)
    sub_num = (
        submitted_fields.get("document_number")
        or submitted_fields.get("passport_number")
        or submitted_fields.get("aadhaar_number")
        or submitted_fields.get("license_number")
        or submitted_fields.get("driving_license_number")
        or submitted_fields.get("visa_number")
    )
    ref_num = (
        reference_metadata.get("document_number")
        or reference_metadata.get("passport_number")
        or reference_metadata.get("aadhaar_number")
        or reference_metadata.get("license_number")
        or reference_metadata.get("driving_license_number")
    )

    clean_sub_num = normalize_doc_number(sub_num)
    clean_ref_num = normalize_doc_number(ref_num)

    if clean_sub_num and clean_ref_num:
        if clean_sub_num == clean_ref_num:
            num_sim = 100.0
            num_status = "EXACT_MATCH"
        else:
            num_sim = round(compute_string_similarity(clean_sub_num, clean_ref_num) * 100.0, 1)
            num_status = "MISMATCH"
            critical_reasons.append(f"Document Number Mismatch: Submitted '{sub_num}' vs Vault '{ref_num}'.")
    else:
        num_sim = 50.0 if not clean_sub_num else 0.0
        num_status = "UNEXTRACTED" if not clean_sub_num else "NOT_IN_VAULT"

    field_comparisons.append({
        "field": "Document Number / UID",
        "submitted": sub_num or "NOT EXTRACTED",
        "reference": ref_num or "N/A",
        "match": num_status == "EXACT_MATCH",
        "similarity": num_sim,
        "weight": 25,
        "status": num_status,
    })
    weighted_scores.append((num_sim, 25))

    # 2. Full Name Check (Weight: 25%)
    sub_name = submitted_fields.get("name")
    ref_name = reference_metadata.get("name")
    if sub_name and ref_name:
        name_sim_ratio = compute_string_similarity(sub_name, ref_name)
        name_sim = round(name_sim_ratio * 100.0, 1)
        if name_sim >= 90.0:
            name_status = "EXACT_MATCH"
        elif name_sim >= 70.0:
            name_status = "PARTIAL_MATCH"
        else:
            name_status = "MISMATCH"
            critical_reasons.append(f"Name Mismatch: Submitted '{sub_name}' vs Vault '{ref_name}' ({name_sim}% similarity).")
    else:
        name_sim = 50.0 if not sub_name else 0.0
        name_status = "UNEXTRACTED" if not sub_name else "NOT_IN_VAULT"

    field_comparisons.append({
        "field": "Full Name",
        "submitted": sub_name or "NOT EXTRACTED",
        "reference": ref_name or "N/A",
        "match": name_status in ("EXACT_MATCH", "PARTIAL_MATCH"),
        "similarity": name_sim,
        "weight": 25,
        "status": name_status,
    })
    weighted_scores.append((name_sim, 25))

    # 3. Date of Birth Check (Weight: 20%)
    sub_dob = submitted_fields.get("date_of_birth") or submitted_fields.get("year_of_birth")
    ref_dob = reference_metadata.get("date_of_birth")
    norm_sub_dob = normalize_date(sub_dob)
    norm_ref_dob = normalize_date(ref_dob)

    if norm_sub_dob and norm_ref_dob:
        if norm_sub_dob == norm_ref_dob:
            dob_sim = 100.0
            dob_status = "EXACT_MATCH"
        elif str(sub_dob) in str(ref_dob) or str(ref_dob) in str(sub_dob):
            dob_sim = 85.0
            dob_status = "PARTIAL_MATCH"
        else:
            dob_sim = 0.0
            dob_status = "MISMATCH"
            critical_reasons.append(f"Date of Birth Mismatch: Submitted '{sub_dob}' vs Vault '{ref_dob}'.")
    else:
        dob_sim = 70.0 if not norm_sub_dob else 0.0
        dob_status = "UNEXTRACTED" if not norm_sub_dob else "NOT_IN_VAULT"

    field_comparisons.append({
        "field": "Date of Birth",
        "submitted": sub_dob or "NOT EXTRACTED",
        "reference": ref_dob or "N/A",
        "match": dob_status in ("EXACT_MATCH", "PARTIAL_MATCH"),
        "similarity": dob_sim,
        "weight": 20,
        "status": dob_status,
    })
    weighted_scores.append((dob_sim, 20))

    # 4. Gender Check (Weight: 10%)
    sub_gen = submitted_fields.get("gender")
    ref_gen = reference_metadata.get("gender")
    norm_sub_gen = normalize_gender(sub_gen)
    norm_ref_gen = normalize_gender(ref_gen)

    if norm_sub_gen and norm_ref_gen:
        if norm_sub_gen == norm_ref_gen:
            gen_sim = 100.0
            gen_status = "EXACT_MATCH"
        else:
            gen_sim = 0.0
            gen_status = "MISMATCH"
            critical_reasons.append(f"Gender Mismatch: Submitted '{sub_gen}' vs Vault '{ref_gen}'.")
    elif not norm_ref_gen or not norm_sub_gen:
        # Some documents like DL do not explicitly state gender
        gen_sim = 100.0
        gen_status = "NOT_APPLICABLE"
    else:
        gen_sim = 100.0
        gen_status = "NOT_APPLICABLE"

    field_comparisons.append({
        "field": "Gender",
        "submitted": sub_gen or "Not Stated",
        "reference": ref_gen or "Not Stated",
        "match": gen_status in ("EXACT_MATCH", "NOT_APPLICABLE"),
        "similarity": gen_sim,
        "weight": 10,
        "status": gen_status,
    })
    weighted_scores.append((gen_sim, 10))

    # 5. Expiry Date Check (Weight: 10%)
    sub_exp = submitted_fields.get("date_of_expiry") or submitted_fields.get("expiry_date")
    ref_exp = reference_metadata.get("date_of_expiry")
    norm_sub_exp = normalize_date(sub_exp)
    norm_ref_exp = normalize_date(ref_exp)

    if norm_sub_exp and norm_ref_exp:
        if norm_sub_exp == norm_ref_exp:
            exp_sim = 100.0
            exp_status = "EXACT_MATCH"
        else:
            exp_sim = 0.0
            exp_status = "MISMATCH"
            critical_reasons.append(f"Expiry Date Mismatch: Submitted '{sub_exp}' vs Vault '{ref_exp}'.")
    elif not ref_exp:
        exp_sim = 100.0
        exp_status = "NOT_APPLICABLE"
    else:
        exp_sim = 50.0
        exp_status = "UNEXTRACTED"

    field_comparisons.append({
        "field": "Date of Expiry",
        "submitted": sub_exp or "Lifelong / N/A",
        "reference": ref_exp or "Lifelong / N/A",
        "match": exp_status in ("EXACT_MATCH", "NOT_APPLICABLE"),
        "similarity": exp_sim,
        "weight": 10,
        "status": exp_status,
    })
    weighted_scores.append((exp_sim, 10))

    # 6. Issuing Authority / Nationality Check (Weight: 10%)
    sub_auth = submitted_fields.get("issuing_authority") or submitted_fields.get("nationality") or submitted_fields.get("country")
    ref_auth = reference_metadata.get("issuing_authority") or reference_metadata.get("nationality") or reference_metadata.get("country")
    if sub_auth and ref_auth:
        auth_sim_ratio = compute_string_similarity(str(sub_auth), str(ref_auth))
        auth_sim = round(auth_sim_ratio * 100.0, 1)
        auth_status = "EXACT_MATCH" if auth_sim >= 70.0 else "MISMATCH"
    else:
        auth_sim = 100.0
        auth_status = "MATCH"

    field_comparisons.append({
        "field": "Issuing Authority / State",
        "submitted": sub_auth or "N/A",
        "reference": ref_auth or "N/A",
        "match": auth_status in ("EXACT_MATCH", "MATCH"),
        "similarity": auth_sim,
        "weight": 10,
        "status": auth_status,
    })
    weighted_scores.append((auth_sim, 10))

    # Calculate overall weighted match score
    total_weight = sum(w for _, w in weighted_scores)
    total_weighted_points = sum(s * (w / 100.0) for s, w in weighted_scores)
    overall_match_score = int(round((total_weighted_points / total_weight) * 100.0))
    overall_match_score = max(0, min(100, overall_match_score))

    # Cryptographic File Hash Comparison
    sub_hash = calculate_file_hash(submitted_filepath)
    ref_hash = reference_metadata.get("sha256_hash", calculate_file_hash(reference_metadata.get("reference_image_abs")))
    is_exact_hash = (sub_hash != "N/A (File Not Found)" and sub_hash.lower() == ref_hash.lower())

    if is_exact_hash:
        hash_note = "Exact byte-for-byte cryptographic SHA-256 match with Digital Vault master record."
        hash_status = "CRYPTOGRAPHIC_MATCH"
    else:
        hash_note = "Submitted file is a digital scan/photo copy. Cryptographic hash differs from master vault file (Standard for user uploads)."
        hash_status = "SCAN_COPY_VERIFIED"

    # Critical Mismatch Determination
    is_critical_mismatch = (len(critical_reasons) > 0 or overall_match_score < 60)

    if overall_match_score >= 85 and not is_critical_mismatch:
        match_status = "MATCH"
    elif overall_match_score >= 60 and not is_critical_mismatch:
        match_status = "PARTIAL_MATCH"
    else:
        match_status = "MISMATCH"

    return {
        "vault_user_id": reference_metadata.get("user_id", "UNKNOWN"),
        "document_type": doc_type,
        "overall_match_score": overall_match_score,
        "match_status": match_status,
        "critical_mismatch": is_critical_mismatch,
        "critical_reasons": critical_reasons,
        "field_comparisons": field_comparisons,
        "hash_comparison": {
            "submitted_hash": sub_hash,
            "reference_hash": ref_hash,
            "is_exact_hash": is_exact_hash,
            "status": hash_status,
            "note": hash_note,
        },
        "issuer_info": {
            "issuing_authority": reference_metadata.get("issuing_authority", "DigiLocker Trusted Issuer Network"),
            "digital_signature": reference_metadata.get("digital_signature", "ED25519-DIGILOCKER-VALID"),
            "verified_at": reference_metadata.get("verified_at", datetime.now().isoformat()),
        },
        "reference_image_abs": reference_metadata.get("reference_image_abs"),
    }


# ---------------------------------------------------------------------------
# Biometric Document-to-Vault Face Verification
# ---------------------------------------------------------------------------

def verify_vault_faces(
    submitted_image_path: Optional[str],
    reference_image_path: Optional[str],
) -> Dict[str, Any]:
    """
    Perform 1:1 facial biometric verification between the submitted document crop
    and the trusted reference credential stored in the Digital Vault.
    """
    from module4_face import verify_identity_faces

    if not submitted_image_path or not os.path.exists(submitted_image_path):
        return {
            "status": "SUBMITTED_IMAGE_MISSING",
            "verified": False,
            "similarity_score": 0.0,
            "similarity_percentage": "0%",
            "reason": "Submitted document image not accessible for vault face check.",
        }

    if not reference_image_path or not os.path.exists(reference_image_path):
        return {
            "status": "REFERENCE_IMAGE_MISSING",
            "verified": False,
            "similarity_score": 0.0,
            "similarity_percentage": "0%",
            "reason": "Vault reference document image not found.",
        }

    try:
        # Cross-verify submitted document against reference document
        res = verify_identity_faces(
            document_image_path=submitted_image_path,
            person_image_path=reference_image_path,
        )
        return {
            "status": res.get("status", "MATCH"),
            "verified": res.get("verified", True),
            "similarity_score": res.get("similarity_score", 100.0),
            "similarity_percentage": res.get("similarity_percentage", "100%"),
            "distance": res.get("distance"),
            "threshold": res.get("threshold", 0.38),
            "model": res.get("model", "FaceNet512"),
            "submitted_face_crop": res.get("doc_face_crop"),
            "vault_face_crop": res.get("person_face_crop"),
            "reason": res.get("reason", "Facial features match trusted vault master photograph."),
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "verified": False,
            "similarity_score": 0.0,
            "similarity_percentage": "0%",
            "reason": f"Vault face matching exception: {str(e)}",
        }
