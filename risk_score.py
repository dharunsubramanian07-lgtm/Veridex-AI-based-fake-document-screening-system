"""
Risk Score wrapper for backwards compatibility with FastAPI / external callers.
Delegates to module5_risk.calculate_risk.
"""

from module5_risk import calculate_risk


def calculate_risk_score(mrz_data: dict, validation_result: dict, tampering_result: dict, face_result: dict) -> dict:
    risk = calculate_risk(validation_result, tampering_result, face_result)
    return {
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "verdict": risk["decision"],
        "components": risk["components"],
        "reasons": risk["reasons"],
    }
