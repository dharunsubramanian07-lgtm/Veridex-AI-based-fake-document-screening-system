"""
Synthetic / Demo Watchlist & Lookout Circular (LOC) Database
Ministry of Home Affairs / Sashastra Seema Bal (SSB) Prototype

NOTICE: All records are synthetic demo data created for hackathon evaluation.
No real sensitive government database is exposed.
"""

from typing import Optional, Dict, Any, List

# Synthetic Watchlist Records
SYNTHETIC_WATCHLIST: List[Dict[str, Any]] = [
    {
        "alert_id": "LOC-MHA-2026-0891",
        "category": "Lookout Circular (LOC) - Active",
        "agency": "Ministry of Home Affairs / Bureau of Immigration",
        "name": "VIKRAMADITYA MALHOTRA",
        "passport_number": "J8921456",
        "document_number": "J8921456",
        "nationality": "IND",
        "dob": "14-08-1985",
        "reason": "Economic offences investigation / Non-bailable warrant issued by Special Court",
        "action_required": "IMMEDIATE DETENTION & NOTIFY IMMIGRATION DESK",
        "severity": "CRITICAL",
    },
    {
        "alert_id": "INTERPOL-RED-2025-4412",
        "category": "Interpol Red Notice",
        "agency": "Interpol / CBI-NCB India",
        "name": "TARIQ AHMED KHAN",
        "passport_number": "P1098234",
        "document_number": "P1098234",
        "nationality": "PAK",
        "dob": "02-11-1979",
        "reason": "Transnational organized cross-border document forgery syndicate",
        "action_required": "DETAIN & ESCORT TO SECONDARY SCREENING FACILITY",
        "severity": "CRITICAL",
    },
    {
        "alert_id": "SSB-BORDER-ALERT-2026-012",
        "category": "Border Intelligence Lookout",
        "agency": "Sashastra Seema Bal (SSB) Intelligence Wing",
        "name": "HAPPYPERSON TRAVELER",
        "passport_number": "555123ABC",
        "document_number": "555123ABC",
        "nationality": "GBR",
        "dob": "05-02-1965",
        "reason": "Flagged for travel document alteration pattern / previous visa overstay",
        "action_required": "MANDATORY SECONDARY BIOMETRIC & DOCUMENT INSPECTION",
        "severity": "HIGH",
    },
    {
        "alert_id": "MHA-SUSP-2026-0341",
        "category": "Suspect Permit Alert",
        "agency": "State Police Intelligence",
        "name": "SURESH KUMAR VERMA",
        "aadhaar_number": "9999 8888 7777",
        "document_number": "9999 8888 7777",
        "nationality": "IND",
        "dob": "11-04-1992",
        "reason": "Duplicate Aadhaar number reported in cross-border permit scam",
        "action_required": "VERIFY PHYSICAL BIOMETRIC AND ORIGINAL SUPPORTING PAPERS",
        "severity": "MEDIUM",
    },
]


def check_watchlist(
    document_number: Optional[str] = None,
    name: Optional[str] = None,
    dob: Optional[str] = None,
    nationality: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query the synthetic watchlist for match candidates based on document number,
    name, or demographic details.
    """
    result = {
        "hit": False,
        "status": "CLEAR",
        "matches": [],
        "summary": "No matching records found in synthetic lookout circulars.",
    }

    if not document_number and not name:
        return result

    clean_doc = str(document_number or "").replace(" ", "").upper().strip()
    clean_name = str(name or "").upper().strip()

    for record in SYNTHETIC_WATCHLIST:
        doc_hit = False
        name_hit = False

        rec_doc = str(record.get("document_number", "")).replace(" ", "").upper().strip()
        rec_pass = str(record.get("passport_number", "")).replace(" ", "").upper().strip()
        rec_aadh = str(record.get("aadhaar_number", "")).replace(" ", "").upper().strip()

        if clean_doc and (clean_doc == rec_doc or clean_doc == rec_pass or clean_doc == rec_aadh):
            doc_hit = True

        rec_name = str(record.get("name", "")).upper()
        if clean_name and (clean_name in rec_name or rec_name in clean_name):
            name_hit = True

        if doc_hit or name_hit:
            result["hit"] = True
            result["status"] = "WATCHLIST_HIT" if record.get("severity") in ["CRITICAL", "HIGH"] else "CAUTION"
            result["matches"].append(record)

    if result["hit"]:
        count = len(result["matches"])
        top = result["matches"][0]
        result["summary"] = (
            f"ALERT: {count} synthetic watchlist match found! "
            f"[{top['category']}] {top['alert_id']} — Reason: {top['reason']} (Action: {top['action_required']})"
        )

    return result


def get_all_watchlist_records() -> List[Dict[str, Any]]:
    """Return all synthetic watchlist records for the admin management view."""
    return SYNTHETIC_WATCHLIST
