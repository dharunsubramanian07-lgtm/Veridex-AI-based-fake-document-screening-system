"""
Module 7: Biometric Multiple-Identity Detection Engine
VERIDEX — AI Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Privacy-by-Design Architecture:
- Stores ONLY 512-D FaceNet floating-point embeddings and masked document numbers.
- NO raw images or full unmasked PII are stored in the identity store.
- Performs 1:N vector cosine similarity search with standard 0.30 threshold.
- Flags "POSSIBLE MULTIPLE IDENTITY" if the same facial biometric is associated with
  multiple different names or document numbers (+40 risk escalation).
- Distinguishes "Repeat Traveller" (same face + same name/doc) with 0 penalty.
"""

import os
import sqlite3
import datetime
from typing import Optional, Dict, Any, List, Union
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "identity_store.db")


# ---------------------------------------------------------------------------
# Database Initialization & Helpers
# ---------------------------------------------------------------------------

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    target = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    return conn


def init_identity_db(db_path: Optional[str] = None) -> None:
    """Initialize SQLite identity store schema if not exists."""
    target = db_path or DEFAULT_DB_PATH
    with get_db_connection(target) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screening_id TEXT,
                name TEXT NOT NULL,
                masked_doc_no TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                embedding BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def mask_doc_number(doc_number: Optional[str]) -> str:
    """Mask document identifier to comply with DPDP Act & Privacy-by-Design."""
    if not doc_number or not isinstance(doc_number, str):
        return "UNKNOWN"
    s = doc_number.strip().replace(" ", "").replace("-", "")
    if len(s) <= 4:
        return "*" * len(s)
    if len(s) == 12 and s.isdigit():
        return f"XXXX-XXXX-{s[-4:]}"
    return f"{s[:2]}{'*' * (len(s) - 4)}{s[-2:]}"


def serialize_embedding(embedding: Union[List[float], np.ndarray]) -> bytes:
    """Convert embedding vector to raw float32 bytes for compact storage."""
    arr = np.asarray(embedding, dtype=np.float32)
    return arr.tobytes()


def deserialize_embedding(blob: bytes) -> np.ndarray:
    """Convert raw byte blob back to float32 numpy array."""
    return np.frombuffer(blob, dtype=np.float32)


def compute_cosine_distance(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """Compute cosine distance between two 1D vectors (0.0 = identical, 1.0 = orthogonal)."""
    e1 = np.asarray(emb1, dtype=np.float32).flatten()
    e2 = np.asarray(emb2, dtype=np.float32).flatten()
    norm1 = np.linalg.norm(e1)
    norm2 = np.linalg.norm(e2)
    if norm1 == 0 or norm2 == 0:
        return 1.0
    similarity = np.dot(e1, e2) / (norm1 * norm2)
    return float(max(0.0, 1.0 - similarity))


# ---------------------------------------------------------------------------
# 1:N Biometric Search & Registration
# ---------------------------------------------------------------------------

def find_matches(
    embedding: Union[List[float], np.ndarray],
    threshold: float = 0.30,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Perform 1:N vector cosine search against all stored synthetic identities."""
    init_identity_db(db_path)
    if embedding is None:
        return []

    target_emb = np.asarray(embedding, dtype=np.float32).flatten()
    matches = []

    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, screening_id, name, masked_doc_no, doc_type, embedding, created_at FROM identities")
            rows = cursor.fetchall()
            for r in rows:
                stored_emb = deserialize_embedding(r["embedding"])
                dist = compute_cosine_distance(target_emb, stored_emb)
                if dist <= threshold:
                    sim_pct = round(max(0.0, (1.0 - dist) * 100.0), 1)
                    matches.append({
                        "id": r["id"],
                        "screening_id": r["screening_id"],
                        "name": r["name"],
                        "masked_doc_no": r["masked_doc_no"],
                        "doc_type": r["doc_type"],
                        "distance": round(dist, 4),
                        "similarity_pct": f"{sim_pct}%",
                        "created_at": r["created_at"],
                    })
    except Exception as e:
        print(f"[module7_identity] Search error: {e}")

    matches.sort(key=lambda m: m["distance"])
    return matches


def register_identity(
    embedding: Union[List[float], np.ndarray],
    name: Optional[str] = None,
    doc_number: Optional[str] = None,
    doc_type: str = "passport",
    screening_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Optional[int]:
    """Store identity vector and masked document identifier."""
    init_identity_db(db_path)
    if embedding is None:
        return None

    try:
        blob = serialize_embedding(embedding)
        clean_name = (name or "UNKNOWN").strip().upper()
        masked_no = mask_doc_number(doc_number)
        clean_type = (doc_type or "passport").lower().strip()
        sc_id = screening_id or f"SCR-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        now_iso = datetime.datetime.now().isoformat()

        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO identities (screening_id, name, masked_doc_no, doc_type, embedding, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sc_id, clean_name, masked_no, clean_type, blob, now_iso))
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"[module7_identity] Registration error: {e}")
        return None


def check_multiple_identity(
    embedding: Optional[Union[List[float], np.ndarray]],
    doc_number: Optional[str] = None,
    name: Optional[str] = None,
    doc_type: str = "passport",
    screening_id: Optional[str] = None,
    threshold: float = 0.30,
    auto_register: bool = True,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Check if a presented facial embedding matches previous identity records.
    - If same face under DIFFERENT name or doc number -> POSSIBLE MULTIPLE IDENTITY (+40 risk)
    - If same face under SAME name and doc number -> REPEAT TRAVELLER (0 risk)
    - If no match -> NEW IDENTITY (registers record)
    """
    init_identity_db(db_path)

    if embedding is None or len(embedding) == 0:
        return {
            "checked": False,
            "multiple_identity_detected": False,
            "status": "NO_EMBEDDING",
            "flag": "SKIPPED",
            "risk_penalty": 0,
            "matching_records": [],
            "reason": "Biometric embedding unavailable for 1:N identity check",
        }

    matches = find_matches(embedding, threshold=threshold, db_path=db_path)
    current_name = (name or "").strip().upper()
    current_masked_no = mask_doc_number(doc_number)

    if not matches:
        new_id = None
        if auto_register:
            new_id = register_identity(
                embedding=embedding,
                name=current_name,
                doc_number=doc_number,
                doc_type=doc_type,
                screening_id=screening_id,
                db_path=db_path,
            )
        return {
            "checked": True,
            "multiple_identity_detected": False,
            "status": "CLEAR",
            "flag": "NEW_IDENTITY",
            "risk_penalty": 0,
            "registered_id": new_id,
            "matching_records": [],
            "reason": "Clear: No prior matching biometric records in synthetic identity database.",
        }

    conflicting_matches = []
    same_identity_matches = []

    for m in matches:
        m_name = m["name"].strip().upper()
        m_doc = m["masked_doc_no"].strip().upper()

        name_match = (m_name == current_name) or (not current_name)
        doc_match = (m_doc == current_masked_no) or (current_masked_no == "UNKNOWN")

        if not name_match or not doc_match:
            conflicting_matches.append(m)
        else:
            same_identity_matches.append(m)

    if conflicting_matches:
        rec_ids = [str(m["id"]) for m in conflicting_matches]
        conflict_details = [
            f"Record #{m['id']} ({m['name']} / {m['masked_doc_no']} / {m['doc_type']}) - Distance: {m['distance']}"
            for m in conflicting_matches
        ]
        return {
            "checked": True,
            "multiple_identity_detected": True,
            "status": "FLAGGED",
            "flag": "POSSIBLE MULTIPLE IDENTITY",
            "risk_penalty": 40,
            "matching_record_ids": rec_ids,
            "matching_records": conflicting_matches,
            "all_matches": matches,
            "reason": f"POSSIBLE MULTIPLE IDENTITY: Face matches prior record(s) under different credentials (IDs: #{', #'.join(rec_ids)})",
            "conflict_details": conflict_details,
        }
    else:
        return {
            "checked": True,
            "multiple_identity_detected": False,
            "status": "PASS",
            "flag": "REPEAT_TRAVELLER",
            "risk_penalty": 0,
            "matching_record_ids": [str(m["id"]) for m in same_identity_matches],
            "matching_records": same_identity_matches,
            "all_matches": matches,
            "reason": "Repeat Traveller: Biometrics match previously recorded credential for the same holder.",
        }


def get_identity_count(db_path: Optional[str] = None) -> int:
    """Return total number of identity embeddings in synthetic store."""
    init_identity_db(db_path)
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM identities")
            return int(cursor.fetchone()[0])
    except Exception:
        return 0


def reset_identity_store(db_path: Optional[str] = None) -> bool:
    """Clear all records from synthetic identity store."""
    init_identity_db(db_path)
    try:
        with get_db_connection(db_path) as conn:
            conn.execute("DELETE FROM identities")
            conn.commit()
            return True
    except Exception as e:
        print(f"[module7_identity] Reset error: {e}")
        return False
