"""
Command Dashboard Analytics Aggregator
VERIDEX — AI Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Aggregates operational screening intelligence from:
1. Immutable Blockchain Ledger (blockchain_ledger.json)
2. Identity Vector Store (identity_store.db)
3. Security Login Audit Trail (security_audit.log)
"""

import os
import sqlite3
import datetime
from typing import Dict, Any, List

from module6_blockchain import global_ledger
from module7_identity import get_identity_count, DEFAULT_DB_PATH


def get_dashboard_metrics() -> Dict[str, Any]:
    """Retrieve synthesized analytics for the executive Command Dashboard."""
    blocks = global_ledger.get_all_blocks()
    screening_blocks = [b for b in blocks if b.get("document_type") != "GENESIS"]

    total_screened = len(screening_blocks)
    low_risk = 0
    med_risk = 0
    high_risk = 0

    doc_type_counts: Dict[str, int] = {}
    flags_by_type: Dict[str, int] = {
        "Watchlist Alert": 0,
        "Template Mismatch": 0,
        "MRZ Mismatch": 0,
        "Image Tampering": 0,
        "Biometric Mismatch": 0,
        "Multiple Identity": 0,
        "Liveness Spoof": 0,
    }

    for b in screening_blocks:
        score = b.get("risk_score", 0)
        dtype = b.get("document_type", "passport").upper()
        doc_type_counts[dtype] = doc_type_counts.get(dtype, 0) + 1

        if score < 30:
            low_risk += 1
        elif score < 70:
            med_risk += 1
        else:
            high_risk += 1

        rec = b.get("ai_recommendation", "")
        if "DETAIN" in rec or score >= 70:
            flags_by_type["Watchlist Alert"] += 1
        if score >= 60:
            flags_by_type["Image Tampering"] += 1

    # Query Identity Store for Multiple-Identity stats
    stored_identities = get_identity_count()
    multi_id_collisions = 0
    try:
        if os.path.exists(DEFAULT_DB_PATH):
            with sqlite3.connect(DEFAULT_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(DISTINCT masked_doc_no) FROM identities")
                doc_distinct = cursor.fetchone()[0]
                multi_id_collisions = max(0, stored_identities - doc_distinct)
    except Exception:
        pass

    flags_by_type["Multiple Identity"] = multi_id_collisions

    # Recent 10 screenings
    recent_screenings = []
    for b in reversed(screening_blocks[-10:]):
        recent_screenings.append({
            "Block #": b.get("index"),
            "Screening ID": b.get("screening_id"),
            "Timestamp": b.get("timestamp")[:19].replace("T", " "),
            "Document": b.get("document_type", "").upper(),
            "Masked ID": b.get("masked_doc_num"),
            "Risk Score": f"{b.get('risk_score')}/100",
            "Action": b.get("ai_recommendation", "CLEAR"),
            "Officer": b.get("officer_id"),
            "Checkpoint": b.get("checkpoint_id"),
            "Block Hash": b.get("block_hash", "")[:12] + "...",
            "Signed": "✓ Ed25519" if b.get("ed25519_signature") else "—",
        })

    integrity = global_ledger.verify_chain_integrity()

    return {
        "total_screened": total_screened,
        "low_risk_count": low_risk,
        "medium_risk_count": med_risk,
        "high_risk_count": high_risk,
        "stored_identities": stored_identities,
        "multi_id_collisions": multi_id_collisions,
        "doc_type_counts": doc_type_counts,
        "flags_by_type": flags_by_type,
        "recent_screenings": recent_screenings,
        "merkle_root": integrity.get("merkle_root", "0" * 64),
        "chain_valid": integrity.get("valid", False),
        "total_blocks": len(blocks),
    }
