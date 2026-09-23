"""
Comprehensive Test Suite for Module 2.5: Document Authenticity & Template Conformance Layer
VERIDEX — AI Identity & Document Screening System (SIH26188)

Covers all 10 mandated test scenarios:
1. Aadhaar matching the supplied structural reference
2. Aadhaar with missing expected region
3. Aadhaar with distorted perspective
4. Aadhaar with different resolution
5. Aadhaar where QR is detectable
6. Aadhaar where QR is unavailable
7. Passport with valid MRZ
8. Passport with MRZ inconsistency
9. Driving licence with generic layout
10. Unsupported driving licence layout
"""

import os
import sys
import unittest
from typing import Optional
import numpy as np
import cv2

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from module2_5_document_authenticity import (
    analyze_document_authenticity,
    detect_document_geometry,
    analyze_qr_codes,
    load_document_profile,
    resolve_best_variant
)
from module5_risk import calculate_risk


def safe_imread(path: str) -> Optional[np.ndarray]:
    """Read image safely on Windows with Unicode path support."""
    if not path or not os.path.exists(path):
        return None
    try:
        data = np.fromfile(path, dtype=np.uint8)
        img = cv2.imdecode(data, cv2.IMREAD_COLOR)
        if img is not None:
            return img
    except Exception:
        pass
    return cv2.imread(path)


def safe_imwrite(path: str, img: np.ndarray) -> bool:
    """Write image safely on Windows with Unicode path support."""
    try:
        ext = os.path.splitext(path)[1]
        ok, buf = cv2.imencode(ext if ext else ".jpg", img)
        if ok:
            buf.tofile(path)
            return True
    except Exception:
        pass
    return cv2.imwrite(path, img)


class TestDocumentAuthenticity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch_dir = os.path.join(BASE_DIR, "test_scratch_auth")
        os.makedirs(cls.scratch_dir, exist_ok=True)
        cls.ref_aadhaar_path = os.path.join(
            BASE_DIR, "document_profiles", "aadhaar", "references", "aadhaar_reference.jpg"
        )

    def _create_synthetic_doc(self, width=600, height=800, color=(240, 245, 250)):
        """Create a synthetic blank document canvas."""
        img = np.full((height, width, 3), color, dtype=np.uint8)
        # Draw border
        cv2.rectangle(img, (10, 10), (width - 10, height - 10), (50, 70, 90), 2)
        return img

    def test_01_aadhaar_matching_structural_reference(self):
        """[TEST 1] Aadhaar matching the supplied structural reference"""
        if not os.path.exists(self.ref_aadhaar_path):
            self.skipTest("Reference image not available on filesystem")

        mock_ocr = {
            "document_type": "aadhaar",
            "name": "SAMPLE HOLDER",
            "date_of_birth": "01/01/1990",
            "aadhaar_number": "8221 8656 5635",
            "raw_text": "GOVERNMENT OF INDIA UNIQUE IDENTIFICATION AUTHORITY OF INDIA MERA AADHAAR MERI PEHCHAN 8221 8656 5635",
            "face_detected": True
        }

        res = analyze_document_authenticity(self.ref_aadhaar_path, document_type="aadhaar", ocr_result=mock_ocr)

        self.assertEqual(res["document_type"], "aadhaar")
        self.assertTrue(res["template_analysis"]["template_available"])
        self.assertGreaterEqual(res["template_analysis"]["template_conformance_score"], 70)
        self.assertIn(res["template_analysis"]["layout_status"], ["CONFORMING", "PARTIALLY_CONFORMING"])
        self.assertTrue(res["reference_analysis"]["reference_available"])
        self.assertTrue(res["reference_analysis"]["privacy_compliant"])
        self.assertGreater(len(res["evidence"]), 0)

    def test_02_aadhaar_missing_expected_region(self):
        """[TEST 2] Aadhaar with missing expected region (e.g. missing photo/header)"""
        img = self._create_synthetic_doc(width=600, height=800)
        fpath = os.path.join(self.scratch_dir, "aadhaar_missing_regions.jpg")
        safe_imwrite(fpath, img)

        # Mock OCR without header keywords or photo
        mock_ocr = {
            "document_type": "aadhaar",
            "raw_text": "Random text without authority keywords",
            "face_detected": False
        }

        res = analyze_document_authenticity(fpath, document_type="aadhaar", ocr_result=mock_ocr)
        self.assertIn(res["regions"]["resident_photo"]["status"], ["MISSING", "OPTIONAL_NOT_FOUND", "UNKNOWN"])
        self.assertGreater(len(res["warnings"]), 0)
        # Verify score is penalized compared to full match
        self.assertLess(res["template_analysis"]["template_conformance_score"], 80)

    def test_03_aadhaar_distorted_perspective(self):
        """[TEST 3] Aadhaar with distorted perspective & rotation"""
        if not os.path.exists(self.ref_aadhaar_path):
            self.skipTest("Reference image not available")

        img = safe_imread(self.ref_aadhaar_path)
        if img is None:
            img = self._create_synthetic_doc(width=600, height=800)
        h, w = img.shape[:2]
        # Apply perspective distortion
        pts1 = np.float32([[0, 0], [w, 0], [0, h], [w, h]])
        pts2 = np.float32([[30, 20], [w - 40, 50], [10, h - 30], [w - 20, h - 10]])
        matrix = cv2.getPerspectiveTransform(pts1, pts2)
        distorted = cv2.warpPerspective(img, matrix, (w, h))

        fpath = os.path.join(self.scratch_dir, "aadhaar_distorted.jpg")
        safe_imwrite(fpath, distorted)

        norm_img, geom = detect_document_geometry(fpath)
        self.assertIsNotNone(norm_img)
        self.assertIn("aspect_ratio", geom)
        self.assertGreater(geom["aspect_ratio"], 0.4)

    def test_04_aadhaar_different_resolution(self):
        """[TEST 4] Aadhaar with different resolution (scaled down 50% and 200%)"""
        if not os.path.exists(self.ref_aadhaar_path):
            self.skipTest("Reference image not available")

        img = safe_imread(self.ref_aadhaar_path)
        if img is None:
            img = self._create_synthetic_doc(width=600, height=800)
        small = cv2.resize(img, (0, 0), fx=0.5, fy=0.5)
        fpath_small = os.path.join(self.scratch_dir, "aadhaar_small.jpg")
        safe_imwrite(fpath_small, small)

        mock_ocr = {
            "document_type": "aadhaar",
            "raw_text": "GOVERNMENT OF INDIA UNIQUE IDENTIFICATION AUTHORITY MERA AADHAAR",
            "face_detected": True
        }
        res_small = analyze_document_authenticity(fpath_small, document_type="aadhaar", ocr_result=mock_ocr)
        self.assertTrue(res_small["template_analysis"]["template_available"])
        self.assertGreaterEqual(res_small["template_analysis"]["template_conformance_score"], 60)

    def test_05_aadhaar_qr_detectable(self):
        """[TEST 5] Aadhaar where QR is detectable"""
        # Create image with synthetic QR code
        img = self._create_synthetic_doc(width=600, height=800)
        # Draw high-contrast black & white QR-like square in bottom right
        cv2.rectangle(img, (400, 550), (550, 700), (0, 0, 0), -1)
        cv2.rectangle(img, (420, 570), (530, 680), (255, 255, 255), -1)
        cv2.rectangle(img, (440, 590), (510, 660), (0, 0, 0), -1)

        fpath = os.path.join(self.scratch_dir, "aadhaar_qr_test.jpg")
        safe_imwrite(fpath, img)

        res = analyze_document_authenticity(fpath, document_type="aadhaar")
        # Must always include non-repudiation disclaimer
        self.assertIn("digital_signature_verification", res["qr_analysis"])
        self.assertIn("Not performed", res["qr_analysis"]["digital_signature_verification"])

    def test_06_aadhaar_qr_unavailable_not_classified_fake(self):
        """[TEST 6] Aadhaar where QR is unavailable is NOT classified as fake solely for missing QR"""
        img = self._create_synthetic_doc(width=600, height=800)
        fpath = os.path.join(self.scratch_dir, "aadhaar_no_qr.jpg")
        safe_imwrite(fpath, img)

        mock_ocr = {
            "document_type": "aadhaar",
            "raw_text": "GOVERNMENT OF INDIA UNIQUE IDENTIFICATION AUTHORITY MERA AADHAAR 8221 8656 5635",
            "face_detected": True
        }
        res = analyze_document_authenticity(fpath, document_type="aadhaar", ocr_result=mock_ocr)
        self.assertFalse(res["qr_analysis"]["qr_detected"])
        # Conformance status should still be legitimate/review, not automatically failed
        self.assertNotEqual(res["template_analysis"]["layout_status"], "NON_CONFORMING")

    def test_07_passport_valid_mrz(self):
        """[TEST 7] Passport with valid ICAO 9303 MRZ and structural layout"""
        img = self._create_synthetic_doc(width=800, height=550)
        fpath = os.path.join(self.scratch_dir, "passport_valid_mrz.jpg")
        safe_imwrite(fpath, img)

        mock_ocr = {
            "document_type": "passport",
            "passport_number": "P1234567",
            "mrz_detected": True,
            "mrz_valid": True,
            "raw_text": "PASSPORT REPUBLIC OF INDIA P<INDSURNAME<<GIVEN<NAMES<<<<<<<<<<<<<<<<<<<\nP1234567<8IND9001015M3001012<<<<<<<<<<<<<<04",
            "face_detected": True
        }
        res = analyze_document_authenticity(fpath, document_type="passport", ocr_result=mock_ocr)
        self.assertEqual(res["document_type"], "passport")
        self.assertTrue(res["mrz_analysis"]["mrz_checksum_valid"])
        self.assertIn(res["template_analysis"]["layout_status"], ["CONFORMING", "PARTIALLY_CONFORMING"])

    def test_08_passport_mrz_inconsistency(self):
        """[TEST 8] Passport with MRZ inconsistency (checksum failure / mismatch)"""
        img = self._create_synthetic_doc(width=800, height=550)
        fpath = os.path.join(self.scratch_dir, "passport_bad_mrz.jpg")
        safe_imwrite(fpath, img)

        mock_ocr = {
            "document_type": "passport",
            "passport_number": "P1234567",
            "mrz_detected": True,
            "mrz_valid": False,  # Checksum failed
            "raw_text": "PASSPORT REPUBLIC OF INDIA P<INDSURNAME<<GIVEN<NAMES<<<<<<<<<<<<<<<<<<<\nINVALID_MRZ_CHECKSUMS<<<<<<<<<<<<<<<<<<00",
            "face_detected": True
        }
        res = analyze_document_authenticity(fpath, document_type="passport", ocr_result=mock_ocr)
        self.assertFalse(res["mrz_analysis"]["mrz_checksum_valid"])
        self.assertGreater(len(res["warnings"]), 0)

    def test_09_driving_licence_generic_layout(self):
        """[TEST 9] Driving licence with generic Indian layout"""
        img = self._create_synthetic_doc(width=850, height=540)
        fpath = os.path.join(self.scratch_dir, "dl_generic.jpg")
        safe_imwrite(fpath, img)

        mock_ocr = {
            "document_type": "driving_license",
            "license_number": "MH1420110062821",
            "raw_text": "UNION OF INDIA TRANSPORT DEPARTMENT DRIVING LICENCE MH1420110062821 NAME S/O DOB",
            "face_detected": True
        }
        res = analyze_document_authenticity(fpath, document_type="driving_license", ocr_result=mock_ocr)
        self.assertEqual(res["document_type"], "driving_license")
        self.assertTrue(res["template_analysis"]["is_generic_profile"])
        self.assertIn("generic", res["template_analysis"]["variant_id"].lower())

    def test_10_unsupported_driving_licence_layout_graceful_review(self):
        """[TEST 10] Unsupported driving licence layout returns low confidence / review rather than fake"""
        # Create unusual aspect ratio (e.g. 0.3 tall narrow strip)
        img = self._create_synthetic_doc(width=300, height=1000)
        fpath = os.path.join(self.scratch_dir, "dl_odd_layout.jpg")
        safe_imwrite(fpath, img)

        mock_ocr = {
            "document_type": "driving_license",
            "raw_text": "Unknown foreign licence text without standard keywords",
            "face_detected": False
        }
        res = analyze_document_authenticity(fpath, document_type="driving_license", ocr_result=mock_ocr)
        # Should NOT crash, returns explainable result with warnings
        self.assertIn("warnings", res)
        self.assertIn(res["template_analysis"]["layout_status"], ["PARTIALLY_CONFORMING", "NON_CONFORMING"])

    def test_11_face_mismatch_produces_high_risk_and_checking_recommendation(self):
        """[TEST 11] Face mismatch with high probability produces HIGH RISK with checking of person recommended"""
        mock_validation = {"status": "PASS", "issues": []}
        mock_tampering = {"tampering_score": 0, "signals": []}
        mock_face = {
            "status": "MISMATCH",
            "similarity_percentage": "22.5%",
            "similarity_score": 22.5,
            "distance": 0.72,
            "reason": "Biometric Mismatch: Presented face does not match document photo (22.5% similarity). Checking of the person is recommended.",
        }

        risk = calculate_risk(mock_validation, mock_tampering, mock_face)
        self.assertEqual(risk["risk_level"], "HIGH")
        self.assertEqual(risk["recommended_action"], "DETAIN & ESCALATE")
        self.assertGreaterEqual(risk["risk_score"], 70)
        self.assertLessEqual(risk["risk_score"], 100)
        self.assertIn("Checking of the person is recommended", risk["action_summary"])

    def test_12_borderline_face_review_displays_verification_recommended_all_other_ok(self):
        """[TEST 12] Borderline face review displays verification recommended with other checks OK"""
        mock_validation = {"status": "PASS", "issues": []}
        mock_tampering = {"tampering_score": 0, "signals": []}
        mock_face = {
            "status": "REVIEW",
            "similarity_percentage": "56.8%",
            "similarity_score": 56.8,
            "distance": 0.5600,
            "reason": "Borderline Face Match: 56.8% (Distance: 0.5600) — Verification recommended for face verification (All other document checks are OK)",
        }

        risk = calculate_risk(mock_validation, mock_tampering, mock_face)
        self.assertEqual(risk["risk_level"], "MEDIUM")
        self.assertEqual(risk["recommended_action"], "SECONDARY INSPECTION")
        self.assertGreaterEqual(risk["risk_score"], 50)
        self.assertLessEqual(risk["risk_score"], 70)
        self.assertIn("Verification recommended for face verification", risk["action_summary"])
        self.assertIn("All other document checks", risk["action_summary"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
