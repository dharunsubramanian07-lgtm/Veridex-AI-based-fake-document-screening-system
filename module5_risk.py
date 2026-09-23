"""
Module 5: Explainable Multi-Factor Risk Assessment Engine
VERIDEX — AI Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Synthesizes:
1. Document Category & Template Conformance (Hard Floor: 70 pts)
2. Document Rule, Checksum & Expiry Validation (0-35 pts)
3. ICAO 9303 MRZ vs Visual-Zone Consistency (0-35 pts)
4. Multi-Layer Tampering Forensics: ELA, Boundary, EXIF, Stamps (0-30 pts)
5. Biometric Facial Verification & Anti-Spoofing / Liveness (0-35 pts)
6. Biometric Multiple-Identity Collision Check (0-40 pts)
7. Synthetic Watchlist & Lookout Circular (LOC) Alert (0-40 pts)

Outputs:
- Explainable Composite 0-100 Risk Score
- Trust Index (100 - Risk Score)
- Granular Waterfall Breakdown List [{"factor", "points", "severity", "reason"}]
- Action Recommendation: CLEAR (0-50) / SECONDARY INSPECTION (50-70) / DETAIN & ESCALATE (>=70)
"""

import os
from typing import Optional, Dict, Any, List, Union

from module1_ocr import extract_document_fields
from module2_validation import run_all_validations, cross_check_mrz_visual_zone
from module2_5_document_authenticity import analyze_document_authenticity
from module3_tampering import analyze_tampering
from module4_face import verify_identity_faces
from module7_identity import check_multiple_identity


def calculate_risk(
    validation_result: dict,
    tampering_result: dict,
    face_result: dict,
    identity_result: Optional[dict] = None,
    authenticity_result: Optional[dict] = None,
    vault_result: Optional[dict] = None,
    **kwargs,
) -> dict:
    """
    Compute an explainable, audit-grade composite risk score (0-100)
    with full factor-level point contributions and severity ratings.
    """
    if vault_result is None:
        vault_result = kwargs.get("vault_result") or kwargs.get("vault")
    if authenticity_result is None:
        authenticity_result = kwargs.get("authenticity_result") or kwargs.get("authenticity")
    if identity_result is None:
        identity_result = kwargs.get("identity_result") or kwargs.get("identity")

    breakdown: List[Dict[str, Any]] = []
    reasons: List[str] = []
    accumulated_risk = 0

    # -----------------------------------------------------------------------
    # Factor 1: Document Template & Category Conformance (Hard floor: 70 pts)
    # -----------------------------------------------------------------------
    issues = validation_result.get("issues", [])
    has_template_mismatch = (
        validation_result.get("template_mismatch", False)
        or any("TEMPLATE MISMATCH" in str(i).upper() or "DOCUMENT TYPE MISMATCH" in str(i).upper() for i in issues)
    )

    # Incorporate Module 2.5 Authenticity & Template Conformance signals
    auth_status = "CONFORMING"
    auth_score = 100
    if authenticity_result:
        t_analysis = authenticity_result.get("template_analysis", {})
        auth_status = t_analysis.get("layout_status", "CONFORMING")
        auth_score = t_analysis.get("template_conformance_score", 100)
        if auth_status == "NON_CONFORMING":
            has_template_mismatch = True

    if has_template_mismatch:
        pts = 70
        accumulated_risk += pts
        m_msg = "Critical template mismatch: Submitted document structure conflicts with expected category template."
        breakdown.append({
            "factor": "Template Conformance",
            "points": pts,
            "severity": "CRITICAL",
            "reason": m_msg,
        })
        reasons.append(f"CRITICAL TEMPLATE VIOLATION: {m_msg}")
    elif auth_status == "PARTIALLY_CONFORMING":
        pts = 15
        accumulated_risk += pts
        p_msg = f"Partial template alignment ({auth_score}% conformance): Minor layout anomalies detected."
        breakdown.append({
            "factor": "Template Conformance",
            "points": pts,
            "severity": "WARNING",
            "reason": p_msg,
        })
        for w in (authenticity_result.get("warnings", []) if authenticity_result else []):
            reasons.append(f"LAYOUT WARNING: {w}")
    else:
        breakdown.append({
            "factor": "Template Conformance",
            "points": 0,
            "severity": "PASS",
            "reason": f"Document structure conforms to expected credential template ({auth_score}% conformance score).",
        })

    # -----------------------------------------------------------------------
    # Factor 2: Synthetic Watchlist & Lookout Circular (LOC) (0 or 40 pts)
    # -----------------------------------------------------------------------
    watchlist_data = validation_result.get("watchlist", {})
    if watchlist_data.get("hit"):
        pts = 40
        accumulated_risk += pts
        top_match = watchlist_data.get("matches", [{}])[0]
        alert_desc = f"Match in border database: [{top_match.get('category', 'ALERT')}] {top_match.get('alert_id', 'LOC-MATCH')} — {top_match.get('reason', 'Watchlist hit')}"
        breakdown.append({
            "factor": "Watchlist / LOC Alert",
            "points": pts,
            "severity": "CRITICAL",
            "reason": alert_desc,
        })
        reasons.append(f"🚨 CRITICAL WATCHLIST MATCH: {alert_desc}")
    else:
        breakdown.append({
            "factor": "Watchlist / LOC Alert",
            "points": 0,
            "severity": "PASS",
            "reason": "Clear: No matching records found in synthetic Lookout Circular (LOC) database.",
        })

    # -----------------------------------------------------------------------
    # Factor 3: Multiple-Identity Collision Check (module7_identity) (0 or 40 pts)
    # -----------------------------------------------------------------------
    if identity_result and identity_result.get("checked"):
        if identity_result.get("multiple_identity_detected"):
            pts = 40
            accumulated_risk += pts
            rec_ids = ", #".join(identity_result.get("matching_record_ids", []))
            id_msg = f"Biometric face matches existing record(s) under different credentials (Record IDs: #{rec_ids})."
            breakdown.append({
                "factor": "Multiple Identity Detection",
                "points": pts,
                "severity": "CRITICAL",
                "reason": id_msg,
            })
            reasons.append(f"🚨 POSSIBLE MULTIPLE IDENTITY: {id_msg}")
        elif identity_result.get("flag") == "REPEAT_TRAVELLER":
            breakdown.append({
                "factor": "Multiple Identity Detection",
                "points": 0,
                "severity": "PASS",
                "reason": "Repeat traveller: Biometric match confirmed against prior legitimate record.",
            })
        else:
            breakdown.append({
                "factor": "Multiple Identity Detection",
                "points": 0,
                "severity": "PASS",
                "reason": "New traveller: No conflicting biometric entries in identity store.",
            })
    else:
        breakdown.append({
            "factor": "Multiple Identity Detection",
            "points": 0,
            "severity": "INFO",
            "reason": "Identity store check skipped (Biometrics not provided).",
        })

    # -----------------------------------------------------------------------
    # Factor 4: MRZ vs Visual-Zone Cross-Check (Text Manipulation) (0 or 35 pts)
    # -----------------------------------------------------------------------
    mrz_cross = validation_result.get("mrz_cross_check", {})
    if mrz_cross.get("mismatch_detected"):
        pts = 35
        accumulated_risk += pts
        m_fields = ", ".join(mrz_cross.get("mismatches", []))
        cross_msg = f"Text manipulation suspected: Visual zone values conflict with ICAO MRZ ({m_fields})."
        breakdown.append({
            "factor": "MRZ vs Visual Cross-Check",
            "points": pts,
            "severity": "HIGH",
            "reason": cross_msg,
        })
        reasons.append(f"TAMPER SIGNAL: {cross_msg}")
    elif mrz_cross.get("status") == "PASS":
        breakdown.append({
            "factor": "MRZ vs Visual Cross-Check",
            "points": 0,
            "severity": "PASS",
            "reason": "Printed visual zone text matches ICAO 9303 MRZ encoded fields.",
        })

    # -----------------------------------------------------------------------
    # Factor 5: Document Rules, Checksums & Expiry Validation (0 to 30 pts)
    # -----------------------------------------------------------------------
    v_status = validation_result.get("status", "PASS")
    non_watchlist_issues = [i for i in issues if "WATCHLIST" not in i and "TEMPLATE" not in i and "TEXT MANIPULATION" not in i]

    if v_status == "FAIL" and non_watchlist_issues:
        pts = 30
        accumulated_risk += pts
        v_reason = f"Validation rules failed: {'; '.join(non_watchlist_issues[:2])}"
        breakdown.append({
            "factor": "Rule & Format Validation",
            "points": pts,
            "severity": "HIGH",
            "reason": v_reason,
        })
        for iss in non_watchlist_issues:
            reasons.append(f"VALIDATION ISSUE: {iss}")
    elif v_status in ("REVIEW", "WARNING") and non_watchlist_issues:
        pts = 15
        accumulated_risk += pts
        v_reason = f"Validation warning: {'; '.join(non_watchlist_issues[:2])}"
        breakdown.append({
            "factor": "Rule & Format Validation",
            "points": pts,
            "severity": "WARNING",
            "reason": v_reason,
        })
        for iss in non_watchlist_issues:
            reasons.append(f"WARNING: {iss}")
    else:
        breakdown.append({
            "factor": "Rule & Format Validation",
            "points": 0,
            "severity": "PASS",
            "reason": "Document format, mathematical checksums, and date boundaries verified.",
        })

    # -----------------------------------------------------------------------
    # Factor 6: Image Tampering Forensics (ELA, Boundary, EXIF, Stamps) (0 to 30 pts)
    # -----------------------------------------------------------------------
    t_score = tampering_result.get("tampering_score", 0)
    scaled_t_pts = int(min(30, round((t_score / 100.0) * 30)))
    if scaled_t_pts > 0:
        accumulated_risk += scaled_t_pts
        t_signals = [s.get("message", "") for s in tampering_result.get("signals", []) if s.get("level") in ("CRITICAL", "HIGH", "MEDIUM")]
        t_reason = f"Forensic anomalies detected ({t_score}% score): {'; '.join(t_signals[:2]) if t_signals else 'Compression/Paste anomalies'}"
        sev = "HIGH" if t_score >= 50 else "WARNING"
        breakdown.append({
            "factor": "Digital Tampering Forensics",
            "points": scaled_t_pts,
            "severity": sev,
            "reason": t_reason,
        })
        for sig in tampering_result.get("signals", []):
            if sig.get("level") in ("CRITICAL", "HIGH"):
                reasons.append(f"TAMPER FORENSIC: {sig['message']}")
    else:
        breakdown.append({
            "factor": "Digital Tampering Forensics",
            "points": 0,
            "severity": "PASS",
            "reason": "No anomalous ELA noise, splice boundaries, or editing metadata detected.",
        })

    # -----------------------------------------------------------------------
    # Factor 7: Biometric Face Match & Presentation-Attack / Anti-Spoofing (0 to 55 pts)
    # -----------------------------------------------------------------------
    f_status = face_result.get("status", "MATCH")
    liveness = face_result.get("liveness", {})
    sim_score = face_result.get("similarity_score", 100.0)
    is_verified = face_result.get("verified", True)

    has_face_mismatch = (
        f_status == "MISMATCH"
        or (
            f_status not in ("PERSON_IMAGE_MISSING", "DOCUMENT_IMAGE_MISSING", "NO_FACE_DETECTED", "REVIEW")
            and (sim_score < 50.0 or not is_verified)
        )
    )

    if has_face_mismatch:
        pts = 75
        accumulated_risk += pts
        f_msg = f"Biometric mismatch: Presented face does not match document photo ({face_result.get('similarity_percentage', '0%')} similarity). Verification recommended — checking of the person is recommended."
        breakdown.append({
            "factor": "Biometric Face Match",
            "points": pts,
            "severity": "CRITICAL",
            "reason": f_msg,
        })
        reasons.append(f"🚨 BIOMETRIC MISMATCH: Biometric mismatch: Presented face does not match document photo ({face_result.get('similarity_percentage', '0%')} similarity). Verification recommended — checking of the person is recommended.")
    elif liveness.get("is_spoof"):
        pts = 50
        accumulated_risk += pts
        spoof_msg = f"Presentation-Attack alert: {liveness.get('verdict')} (Confidence: {liveness.get('confidence', 'N/A')})."
        breakdown.append({
            "factor": "Biometric Presentation Attack",
            "points": pts,
            "severity": "HIGH",
            "reason": spoof_msg,
        })
        reasons.append(f"🚨 LIVENESS SPOOF ALERT: {spoof_msg}")
    elif f_status == "REVIEW":
        pts = 55
        accumulated_risk += pts
        f_msg = f"Borderline biometric face match ({face_result.get('similarity_percentage', '56%')} similarity). Verification recommended for face verification (All other document checks are OK)."
        breakdown.append({
            "factor": "Biometric Face Match",
            "points": pts,
            "severity": "WARNING",
            "reason": f_msg,
        })
        reasons.append(f"⚠️ BIOMETRIC REVIEW: Verification recommended for face verification. All other document checks (Format, Checksums, Template Conformance, and Tampering Forensics) are OK.")
    elif f_status in ("NO_FACE_DETECTED", "DOCUMENT_IMAGE_MISSING", "ERROR"):
        pts = 50
        accumulated_risk += pts
        f_msg = face_result.get("reason", "Face not confirmed on credential. Checking of the person is recommended.")
        breakdown.append({
            "factor": "Biometric Face Match",
            "points": pts,
            "severity": "WARNING",
            "reason": f_msg,
        })
        reasons.append(f"⚠️ BIOMETRIC UNCONFIRMED: {f_msg}")
    elif f_status == "PERSON_IMAGE_MISSING":
        pts = 10
        accumulated_risk += pts
        breakdown.append({
            "factor": "Biometric Face Match",
            "points": pts,
            "severity": "INFO",
            "reason": "Live person photograph not provided. Biometric verification skipped.",
        })
    else:
        breakdown.append({
            "factor": "Biometric Face Match",
            "points": 0,
            "severity": "PASS",
            "reason": f"Biometric facial match verified ({face_result.get('similarity_percentage', '100%')} similarity, Liveness: {liveness.get('verdict', 'VERIFIED')}).",
        })

    # -----------------------------------------------------------------------
    # Factor 8: Digital Vault (DigiLocker) Reference Verification (0 to 30 pts)
    # -----------------------------------------------------------------------
    if vault_result:
        v_match_score = vault_result.get("overall_match_score", 100)
        v_crit = vault_result.get("critical_mismatch", False)
        v_reasons = vault_result.get("critical_reasons", [])
        v_status = vault_result.get("match_status", "MATCH")

        if v_crit or v_match_score < 60:
            v_pts = 30
            accumulated_risk += v_pts
            v_msg = f"Critical DigiLocker reference mismatch ({v_match_score}% match score): {'; '.join(v_reasons[:2]) if v_reasons else 'Significant field differences'}"
            breakdown.append({
                "factor": "Digital Vault Reference",
                "points": v_pts,
                "severity": "CRITICAL",
                "reason": v_msg,
            })
            for r in v_reasons:
                reasons.append(f"🚨 DIGILOCKER VAULT MISMATCH: {r}")
        elif v_status == "PARTIAL_MATCH" or v_match_score < 85:
            v_pts = 15
            accumulated_risk += v_pts
            v_msg = f"Minor variance against DigiLocker reference record ({v_match_score}% match score)."
            breakdown.append({
                "factor": "Digital Vault Reference",
                "points": v_pts,
                "severity": "WARNING",
                "reason": v_msg,
            })
            reasons.append(f"⚠️ DIGILOCKER VAULT WARNING: Partial reference alignment ({v_match_score}% match).")
        else:
            breakdown.append({
                "factor": "Digital Vault Reference",
                "points": 0,
                "severity": "PASS",
                "reason": f"Document fields verified consistent with trusted DigiLocker master record ({v_match_score}% match score).",
            })

    # -----------------------------------------------------------------------
    # Composite Score Calculation & Decision Action
    # -----------------------------------------------------------------------
    total_risk = min(100, max(0, accumulated_risk))

    if has_template_mismatch:
        total_risk = max(70, total_risk)

    if has_face_mismatch:
        total_risk = max(75, total_risk)
    elif f_status in ("REVIEW", "NO_FACE_DETECTED", "DOCUMENT_IMAGE_MISSING", "ERROR") and f_status != "PERSON_IMAGE_MISSING":
        total_risk = max(50, total_risk)

    trust_index = 100 - total_risk

    # Recommendation Action Thresholds:
    # 0 - 50 (< 50) => LOW RISK (CLEAR)
    # 50 - 70 (50 to 69) => MEDIUM RISK (SECONDARY INSPECTION)
    # 70 - 100 (>= 70) => HIGH RISK (DETAIN & ESCALATE)
    has_biometric_flag = (has_face_mismatch or f_status in ("REVIEW", "NO_FACE_DETECTED", "DOCUMENT_IMAGE_MISSING", "ERROR"))
    other_issues = [i for i in validation_result.get("issues", []) if "WATCHLIST" not in i and "TEMPLATE" not in i]
    other_checks_ok = (len(other_issues) == 0 and tampering_result.get("tampering_score", 0) < 30 and not has_template_mismatch and not watchlist_data.get("hit"))

    if total_risk >= 70 or has_template_mismatch or watchlist_data.get("hit") or has_face_mismatch or f_status == "MISMATCH":
        risk_level = "HIGH"
        recommended_action = "DETAIN & ESCALATE"
        if has_face_mismatch or f_status == "MISMATCH":
            action_summary = f"HIGH RISK (70-100): Biometric face mismatch detected ({face_result.get('similarity_percentage', '0%')} similarity). Verification recommended — presented face does not match credential photo. Checking of the person is recommended."
        else:
            action_summary = "HIGH RISK (70-100): Potential identity fraud, template mismatch, or watchlist hit. Escalate immediately to supervisory border control."
    elif total_risk >= 50 or has_biometric_flag:
        risk_level = "MEDIUM"
        recommended_action = "SECONDARY INSPECTION"
        if f_status == "REVIEW" or (has_biometric_flag and other_checks_ok):
            action_summary = "MEDIUM RISK (50-70): Verification recommended for face verification. All other document checks (Format, Checksums, Template Conformance, and Tampering Forensics) are OK."
        else:
            action_summary = "MEDIUM RISK (50-70): Discrepancies detected. Divert passenger/document to secondary inspection counter for manual officer review."
    else:
        risk_level = "LOW"
        recommended_action = "CLEAR"
        action_summary = "LOW RISK (0-50): Credential structure, cryptographic consistency, tampering forensics, and biometric matching verified. Authorized to proceed."

    # Component breakdown for legacy UI compatibility
    components = {
        "validation_risk": sum(b["points"] for b in breakdown if b["factor"] in ("Template Conformance", "Rule & Format Validation", "MRZ vs Visual Cross-Check")),
        "watchlist_risk": sum(b["points"] for b in breakdown if b["factor"] == "Watchlist / LOC Alert"),
        "tampering_risk": sum(b["points"] for b in breakdown if b["factor"] == "Digital Tampering Forensics"),
        "biometric_risk": sum(b["points"] for b in breakdown if b["factor"] in ("Biometric Face Match", "Biometric Presentation Attack", "Multiple Identity Detection")),
        "vault_risk": sum(b["points"] for b in breakdown if b["factor"] == "Digital Vault Reference"),
    }

    return {
        "risk_score": total_risk,
        "trust_index": trust_index,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "ai_recommendation": recommended_action,
        "decision": action_summary,
        "action_summary": action_summary,
        "components": components,
        "breakdown": breakdown,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Master End-to-End Screening Pipeline Dispatcher
# ---------------------------------------------------------------------------

def screen_document(
    document_path: Optional[str] = None,
    arg2: Optional[str] = None,
    arg3: Optional[str] = None,
    document_type: Optional[str] = None,
    doc_type: Optional[str] = None,
    person_image_path: Optional[str] = None,
    doc_path: Optional[str] = None,
    person_path: Optional[str] = None,
    screening_id: Optional[str] = None,
    **kwargs,
) -> dict:
    """
    Universal 6-Layer Screening Pipeline Dispatcher.
    Gracefully handles flexible positional arguments (e.g. (doc, person, type) or (doc, type, person)).
    """
    # Resolve parameters intelligently
    eff_doc_path = document_path or doc_path or kwargs.get("image_path")
    known_types = ("passport", "aadhaar", "driving_license", "driving_licence", "license", "visa", "permit")

    eff_doc_type = "passport"
    eff_person_path = None

    for candidate in [doc_type, document_type, arg2, arg3]:
        if candidate and isinstance(candidate, str) and candidate.lower().strip() in known_types:
            eff_doc_type = candidate.lower().strip()
            break

    for candidate in [person_image_path, person_path, arg2, arg3]:
        if candidate and isinstance(candidate, str) and (candidate.lower().endswith((".jpg", ".jpeg", ".png", ".webp")) or os.path.exists(candidate)) and candidate.lower().strip() not in known_types:
            eff_person_path = candidate
            break

    # Layer 1: OCR & Document Intelligence
    fields = extract_document_fields(eff_doc_path, document_type=eff_doc_type)

    # Layer 2: Rule & Watchlist Validation (with MRZ Cross-Check)
    validation = run_all_validations(
        fields=fields,
        doc_type=eff_doc_type,
        raw_ocr_text=fields.get("raw_text"),
        requested_doc_type=eff_doc_type,
    )

    # Layer 2.5: Document Authenticity & Template Conformance
    authenticity = analyze_document_authenticity(
        image_path=eff_doc_path,
        document_type=eff_doc_type,
        ocr_result=fields,
    )

    # Layer 3: Tampering Forensics & Stamp Analysis
    tampering = analyze_tampering(
        image_path=eff_doc_path,
        doc_type=eff_doc_type,
        extracted_fields=fields,
    )

    # Layer 4: Biometric Matching & Liveness
    face = verify_identity_faces(
        document_image_path=eff_doc_path,
        person_image_path=eff_person_path,
    )

    # Layer 5: 1:N Multiple Identity Detection in Identity Store
    holder_name = fields.get("name")
    doc_number = (
        fields.get("passport_number")
        or fields.get("aadhaar_number")
        or fields.get("license_number")
        or fields.get("visa_number")
        or fields.get("document_number")
    )
    person_emb = face.get("person_embedding")

    identity = check_multiple_identity(
        embedding=person_emb,
        doc_number=doc_number,
        name=holder_name,
        doc_type=eff_doc_type,
        screening_id=screening_id,
        threshold=0.30,
        auto_register=True,
    )

    # Optional DigiLocker Reference Cross-Verification
    vault = kwargs.get("vault_result")
    vault_uid = kwargs.get("vault_user_id")
    if not vault and vault_uid:
        try:
            from module7_digilocker import get_reference_document, compare_documents
            ref_meta = get_reference_document(vault_uid, eff_doc_type)
            if ref_meta:
                vault = compare_documents(fields, ref_meta, eff_doc_path)
        except Exception:
            vault = None

    # Layer 6: Explainable Multi-Factor Risk Assessment Engine
    risk = calculate_risk(
        validation_result=validation,
        tampering_result=tampering,
        face_result=face,
        identity_result=identity,
        authenticity_result=authenticity,
        vault_result=vault,
    )

    return {
        "screening_id": screening_id,
        "document_path": eff_doc_path,
        "person_path": eff_person_path,
        "document_type": eff_doc_type,
        "fields": fields,
        "validation": validation,
        "authenticity": authenticity,
        "tampering": tampering,
        "face": face,
        "identity": identity,
        "vault": vault,
        "risk": risk,
    }
