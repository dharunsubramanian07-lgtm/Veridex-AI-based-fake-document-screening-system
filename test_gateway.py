"""
Automated Test Suite for Module 7: VERIDEX Digital Document Gateway
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from module7_digital_gateway import (
    DEMO_CONFIG,
    CITIZEN_CATALOG,
    verify_gateway_login,
    verify_gateway_otp,
    verify_gateway_pin,
    get_citizen_profile,
    get_citizen_documents,
    get_gateway_document_by_id,
    log_gateway_event,
    get_gateway_activity_logs,
    get_initials,
    get_masked_name,
)


class TestDigitalGateway(unittest.TestCase):
    def test_demo_config(self):
        self.assertIn("default_mobile", DEMO_CONFIG)
        self.assertIn("default_aadhaar", DEMO_CONFIG)
        self.assertIn("default_otp", DEMO_CONFIG)
        self.assertIn("default_pin", DEMO_CONFIG)
        self.assertIn("disclaimer", DEMO_CONFIG)

    def test_initials_and_masking(self):
        self.assertEqual(get_initials("Sriram Mamundi"), "SM")
        self.assertEqual(get_initials("Anna Eriksson"), "AE")
        self.assertEqual(get_initials("Arun"), "AR")
        
        masked = get_masked_name("Sriram Mamundi")
        self.assertTrue(masked.startswith("S") and masked.endswith("M"))
        self.assertIn("*", masked)

    def test_verify_gateway_login(self):
        # Test valid demo mobile
        ok, msg, uid = verify_gateway_login("9999999999", "mobile")
        self.assertTrue(ok)
        self.assertEqual(uid, "VX001")

        # Test valid demo aadhaar
        ok, msg, uid = verify_gateway_login("123456789012", "aadhaar")
        self.assertTrue(ok)
        self.assertEqual(uid, "VX001")

        # Test invalid inputs
        ok, msg, uid = verify_gateway_login("123", "mobile")
        self.assertFalse(ok)

    def test_verify_gateway_otp(self):
        ok, msg = verify_gateway_otp("123456")
        self.assertTrue(ok)

        ok, msg = verify_gateway_otp("12")
        self.assertFalse(ok)

    def test_verify_gateway_pin(self):
        ok, msg = verify_gateway_pin("1234")
        self.assertTrue(ok)

        ok, msg = verify_gateway_pin("123456")
        self.assertTrue(ok)

        ok, msg = verify_gateway_pin("1")
        self.assertFalse(ok)

    def test_citizen_profile_and_documents(self):
        profile = get_citizen_profile("VX001")
        self.assertEqual(profile["full_name"], "Sriram Mamundi")

        docs = get_citizen_documents("VX001")
        self.assertTrue(len(docs) >= 2)

        # Test retrieving specific document
        doc = get_gateway_document_by_id("VX001", "DOC-AADH-001")
        self.assertIsNotNone(doc)
        self.assertEqual(doc["doc_type"], "aadhaar")
        self.assertTrue(os.path.exists(doc["absolute_image_path"]))

    def test_activity_logging(self):
        log_gateway_event("TEST_EVENT", "Testing gateway event logging", "VX001", "Aadhaar Card")
        logs = get_gateway_activity_logs()
        self.assertTrue(len(logs) > 0)
        self.assertEqual(logs[0]["event_type"], "TEST_EVENT")


if __name__ == "__main__":
    unittest.main()
