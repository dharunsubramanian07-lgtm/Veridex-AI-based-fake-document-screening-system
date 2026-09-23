"""
Comprehensive Automated Test Suite for VERIDEX Digital Vault (DigiLocker-Mimic)
Problem Statement: SIH 2026 — AI-Powered Fake Identity & Document Screening System
Theme: Blockchain & Cybersecurity
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from module7_digilocker import (
    load_vault_users,
    get_user_documents,
    get_reference_document,
    compare_documents,
    normalize_date,
    normalize_doc_number,
    normalize_gender,
    calculate_file_hash,
)
from module1_ocr import extract_document_fields
from module5_risk import calculate_risk, screen_document
from module6_blockchain import global_ledger


class TestDigiLockerVault(unittest.TestCase):

    def setUp(self):
        self.sample_dir = os.path.join(BASE_DIR, "sample_docs")
        self.aadhar_path = os.path.join(self.sample_dir, "aadhar1.jpg")
        self.license_path = os.path.join(self.sample_dir, "license.jpg")
        self.passport2_path = os.path.join(self.sample_dir, "passport2.jpg")
        self.tampered_path = os.path.join(self.sample_dir, "passport1_tampered.jpg")

    def test_01_load_vault_users(self):
        """Test loading DigiLocker users store."""
        data = load_vault_users()
        self.assertIn("users", data)
        self.assertGreaterEqual(len(data["users"]), 2)
        user_ids = [u["user_id"] for u in data["users"]]
        self.assertIn("VX001", user_ids)
        self.assertIn("VX002", user_ids)

    def test_02_get_user_documents(self):
        """Test retrieving available documents for users."""
        vx001_docs = get_user_documents("VX001")
        self.assertGreaterEqual(len(vx001_docs), 2)
        doc_types = [d["doc_type"] for d in vx001_docs]
        self.assertIn("aadhaar", doc_types)
        self.assertIn("driving_license", doc_types)

        vx002_docs = get_user_documents("VX002")
        self.assertGreaterEqual(len(vx002_docs), 1)
        self.assertIn("passport", [d["doc_type"] for d in vx002_docs])

    def test_03_get_reference_document(self):
        """Test retrieving master reference metadata and file resolution."""
        ref_aadh = get_reference_document("VX001", "aadhaar")
        self.assertIsNotNone(ref_aadh)
        self.assertEqual(ref_aadh.get("document_type"), "aadhaar")
        self.assertEqual(ref_aadh.get("document_number"), "8416 1590 3267")
        self.assertTrue(os.path.exists(ref_aadh.get("reference_image_abs", "")))

        ref_pass = get_reference_document("VX002", "passport")
        self.assertIsNotNone(ref_pass)
        self.assertEqual(ref_pass.get("document_type"), "passport")
        self.assertEqual(ref_pass.get("document_number"), "D23145890")

    def test_04_normalization_helpers(self):
        """Test robust normalization across dates, numbers, and gender."""
        self.assertEqual(normalize_date("11/04/1992"), "11/04/1992")
        self.assertEqual(normalize_date("1992-04-11"), "11/04/1992")
        self.assertEqual(normalize_date("12-08-1974"), "12/08/1974")

        self.assertEqual(normalize_doc_number(" 8416 1590 3267 "), "841615903267")
        self.assertEqual(normalize_doc_number("tn42-20220004426"), "TN4220220004426")

        self.assertEqual(normalize_gender("M"), "MALE")
        self.assertEqual(normalize_gender("Female"), "FEMALE")

    def test_05_compare_genuine_aadhaar_match(self):
        """Test comparing genuine Aadhaar against VX001 master record (expect MATCH)."""
        ref_meta = get_reference_document("VX001", "aadhaar")
        fields = extract_document_fields(self.aadhar_path, "aadhaar")
        res = compare_documents(fields, ref_meta, self.aadhar_path)

        self.assertGreaterEqual(res["overall_match_score"], 90)
        self.assertEqual(res["match_status"], "MATCH")
        self.assertFalse(res["critical_mismatch"])
        self.assertTrue(res["hash_comparison"]["is_exact_hash"])

    def test_06_compare_driving_license_match(self):
        """Test comparing genuine Driving Licence against VX001 master record (expect MATCH)."""
        ref_meta = get_reference_document("VX001", "driving_license")
        fields = extract_document_fields(self.license_path, "driving_license")
        res = compare_documents(fields, ref_meta, self.license_path)

        self.assertGreaterEqual(res["overall_match_score"], 80)
        self.assertEqual(res["match_status"], "MATCH")
        self.assertFalse(res["critical_mismatch"])

    def test_07_compare_tampered_passport_mismatch(self):
        """Test comparing tampered/altered credential against VX002 reference (expect MISMATCH)."""
        ref_meta = get_reference_document("VX002", "passport")
        fields = extract_document_fields(self.tampered_path, "passport")
        res = compare_documents(fields, ref_meta, self.tampered_path)

        self.assertLess(res["overall_match_score"], 60)
        self.assertEqual(res["match_status"], "MISMATCH")
        self.assertTrue(res["critical_mismatch"])
        self.assertGreater(len(res["critical_reasons"]), 0)

    def test_08_risk_engine_integration(self):
        """Test that risk engine processes vault signals cleanly and respects bounds (0-100)."""
        ref_meta = get_reference_document("VX001", "aadhaar")
        fields = extract_document_fields(self.aadhar_path, "aadhaar")
        vault_match = compare_documents(fields, ref_meta, self.aadhar_path)

        dummy_val = {"issues": [], "status": "PASS", "template_mismatch": False}
        dummy_tamp = {"tampering_score": 0, "signals": []}
        dummy_face = {"status": "MATCH", "similarity_percentage": "100%", "verified": True}

        # 1. Matching Vault -> 0 pts penalty
        risk_match = calculate_risk(dummy_val, dummy_tamp, dummy_face, vault_result=vault_match)
        self.assertIn("vault_risk", risk_match["components"])
        self.assertEqual(risk_match["components"]["vault_risk"], 0)
        self.assertEqual(risk_match["risk_score"], 0)

        # 2. Mismatching Vault -> +30 pts penalty
        ref_pass = get_reference_document("VX002", "passport")
        tampered_fields = extract_document_fields(self.tampered_path, "passport")
        vault_mismatch = compare_documents(tampered_fields, ref_pass, self.tampered_path)

        risk_mismatch = calculate_risk(dummy_val, dummy_tamp, dummy_face, vault_result=vault_mismatch)
        self.assertEqual(risk_mismatch["components"]["vault_risk"], 30)
        self.assertGreaterEqual(risk_mismatch["risk_score"], 30)
        self.assertLessEqual(risk_mismatch["risk_score"], 100)

    def test_09_blockchain_integration(self):
        """Test adding screening record with vault audit metadata and verifying chain."""
        ref_meta = get_reference_document("VX001", "aadhaar")
        fields = extract_document_fields(self.aadhar_path, "aadhaar")
        vault_res = compare_documents(fields, ref_meta, self.aadhar_path)

        block = global_ledger.add_screening_record(
            screening_id="TST-VAULT-9999",
            officer_id="SSB-TEST-OFFICER",
            checkpoint_id="ICP-TEST-01",
            document_type="AADHAAR",
            document_number="8416 1590 3267",
            document_filepath=self.aadhar_path,
            risk_score=0,
            ai_recommendation="CLEAR",
            officer_decision="AUTO_SCREENED",
            vault_data=vault_res,
        )

        self.assertIn("vault_verification", block)
        self.assertEqual(block["vault_verification"]["vault_user_id"], "VX001")
        self.assertEqual(block["vault_verification"]["match_status"], "MATCH")

        integrity = global_ledger.verify_chain_integrity()
        self.assertTrue(integrity["valid"])

    def test_10_end_to_end_screen_document_optionality(self):
        """Test screen_document with vault_user_id and verify backward compatibility without vault."""
        # Case A: Standard screening without vault
        res_no_vault = screen_document(self.aadhar_path, document_type="aadhaar")
        self.assertIsNone(res_no_vault.get("vault"))
        self.assertIn("risk", res_no_vault)

        # Case B: Screening with DigiLocker vault profile
        res_with_vault = screen_document(self.aadhar_path, document_type="aadhaar", vault_user_id="VX001")
        self.assertIsNotNone(res_with_vault.get("vault"))
        self.assertEqual(res_with_vault["vault"]["match_status"], "MATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
