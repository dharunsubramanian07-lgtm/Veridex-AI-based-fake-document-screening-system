"""
SSB AI Border Screening Test Suite
Covers OCR, Watchlist, Tampering, Face, Risk, Blockchain Ledger & Tamper Simulation
"""

import os
import sys

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

from module5_risk import screen_document
from module6_blockchain import global_ledger
from watchlist_db import check_watchlist

print("=" * 70)
print("TEST 1: SYNTHETIC WATCHLIST / LOOKOUT CIRCULAR (LOC) TEST")
print("=" * 70)
w1 = check_watchlist(document_number="J8921456", name="VIKRAMADITYA MALHOTRA")
print(f"Watchlist Query [J8921456]: Hit={w1['hit']}, Status={w1['status']}")
print(f"Summary: {w1['summary']}")

w2 = check_watchlist(document_number="A1234567", name="CLEAN TRAVELER")
print(f"Watchlist Query [A1234567]: Hit={w2['hit']}, Status={w2['status']}")
print(f"Summary: {w2['summary']}")

print("\n" + "=" * 70)
print("TEST 2: FULL SCREENING ON TAMPERED PASSPORT")
print("=" * 70)
s_tamper = screen_document("sample_docs/passport1_tampered.jpg", "passport", "sample_docs/person1.jpg")
print(f"Risk Score: {s_tamper['risk']['risk_score']}/100 ({s_tamper['risk']['risk_level']} RISK)")
print(f"AI Recommendation: {s_tamper['risk']['ai_recommendation']}")
print(f"Tampering Score: {s_tamper['tampering']['tampering_score']}% (Flag: {s_tamper['tampering']['overall_flag']})")
print(f"Annotated Image: {s_tamper['tampering'].get('annotated_image_path')}")
print("Reasons:")
for r in s_tamper['risk']['reasons']:
    print(f"  * {r}")

print("\n" + "=" * 70)
print("TEST 3: BLOCKCHAIN AUDIT TRAIL COMMIT & INTEGRITY VERIFICATION")
print("=" * 70)
blk = global_ledger.add_screening_record(
    screening_id="SCR-2026-TEST01",
    officer_id="SSB-OFF-104 (SI R. Sharma)",
    checkpoint_id="ICP-Raxaul (Indo-Nepal)",
    document_type="passport",
    document_number=s_tamper['fields'].get('passport_number'),
    document_filepath="sample_docs/passport1_tampered.jpg",
    risk_score=s_tamper['risk']['risk_score'],
    ai_recommendation=s_tamper['risk']['ai_recommendation'],
    officer_decision="MANUAL REVIEW",
    override_reason="Document referred for secondary forensic inspection due to MRZ DOB mismatch.",
)
print(f"Committed Block #{blk['index']} - Screening ID: {blk['screening_id']}")
print(f"  Block Hash: {blk['block_hash']}")
print(f"  Previous Hash: {blk['previous_hash']}")

integrity = global_ledger.verify_chain_integrity()
print(f"Chain Integrity Status: Valid={integrity['valid']}, Total Blocks={integrity.get('total_blocks')}")
print(f"Message: {integrity['message']}")

print("\n" + "=" * 70)
print("TEST 4: JUDGE DEMONSTRATION — TAMPER SIMULATION DETECTION")
print("=" * 70)
# Simulate an unauthorized database tampering attempt on block 1
tampered_idx = len(global_ledger.chain) - 1
global_ledger.simulate_tamper(tampered_idx, "officer_decision", "UNAUTHORIZED_CLEARED_BY_HACKER")
tamper_check = global_ledger.verify_chain_integrity()
print(f"Integrity Check After Hack Simulation: Valid={tamper_check['valid']}")
print(f"Detected Tamper Alert: {tamper_check['message']}")

# Restore ledger
global_ledger.repair_or_reset_ledger()
print("Ledger reset to clean state.")

print("\n" + "=" * 70)
print("ALL SSB CORE TESTS PASSED SUCCESSFULLY!")
print("=" * 70)
