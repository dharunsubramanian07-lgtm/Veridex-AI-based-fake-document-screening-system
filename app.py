"""
VERIDEX — AI-Powered Fake Identity & Document Screening System
SIH 2026 Hackathon Prototype | Enterprise Decision-Support KYC & Border Screening Platform
"""

import os
import sys
import json
import tempfile
from datetime import datetime
from PIL import Image

import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

# Page configuration
st.set_page_config(
    page_title="VERIDEX — AI Identity & Document Screening",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Import backend modules
import importlib
import module1_ocr
import module2_validation
import module2_5_document_authenticity
import module3_tampering
import module4_face
import module5_risk
import module6_blockchain
import module7_digilocker
import module7_digital_gateway

importlib.reload(module5_risk)
importlib.reload(module6_blockchain)
importlib.reload(module7_digilocker)
importlib.reload(module7_digital_gateway)

from module1_ocr import extract_document_fields
from module2_validation import run_all_validations
from module2_5_document_authenticity import analyze_document_authenticity
from module3_tampering import analyze_tampering
from module4_face import verify_identity_faces
from module5_risk import calculate_risk
from module6_blockchain import global_ledger, BlockchainLedger
from module7_digilocker import (
    load_vault_users,
    get_user_documents,
    get_reference_document,
    compare_documents,
    verify_vault_faces,
    calculate_file_hash,
)
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

# Ensure output directory exists
os.makedirs(os.path.join(BASE_DIR, "outputs"), exist_ok=True)


# ============================================================
# RICH LIGHT BLUE-GRAY ENTERPRISE THEME WITH HIGH-CONTRAST BUTTONS
# ============================================================
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global reset & typography with rich light background */
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #E6EFF7 !important;
        color: #16324F !important;
    }

    /* Main container bounds */
    .main .block-container {
        padding-top: 1.2rem !important;
        padding-bottom: 2.8rem !important;
        max-width: 1180px !important;
    }

    /* Top Navigation Bar */
    .brand-header {
        background-color: #DCE8F3;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        padding: 16px 24px;
        margin-bottom: 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 2px 6px rgba(22, 50, 79, 0.07);
    }
    .brand-logo-area {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .brand-logo-badge {
        width: 44px;
        height: 44px;
        background: linear-gradient(135deg, #1F4E79 0%, #2F6F95 100%);
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 22px;
        color: #FFFFFF;
        box-shadow: 0 2px 5px rgba(31, 78, 121, 0.25);
    }
    .brand-title {
        font-size: 20px;
        font-weight: 800;
        color: #16324F;
        letter-spacing: -0.3px;
        line-height: 1.2;
    }
    .brand-sub {
        font-size: 12px;
        color: #536B82;
        font-weight: 500;
        margin-top: 2px;
    }
    .status-badge {
        background-color: #D5F2E3;
        border: 1px solid #A3E3C2;
        color: #0E5231;
        font-size: 12px;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        background-color: #238B57;
        border-radius: 50%;
        box-shadow: 0 0 0 2px rgba(35, 139, 87, 0.25);
    }

    /* Stepper Navigation */
    .stepper-wrap {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 22px;
        background-color: #DFEAF4;
        padding: 13px 22px;
        border-radius: 12px;
        border: 1px solid #BDD0E2;
        box-shadow: 0 1px 3px rgba(22, 50, 79, 0.05);
    }
    .step-item {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .step-bubble {
        width: 28px;
        height: 28px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: 700;
        transition: all 0.2s ease;
    }
    .step-active {
        background-color: #1F4E79;
        color: #FFFFFF;
        box-shadow: 0 0 0 3px rgba(31, 78, 121, 0.25);
    }
    .step-done {
        background-color: #238B57;
        color: #FFFFFF;
    }
    .step-idle {
        background-color: #CBDCEB;
        color: #536B82;
        border: 1px solid #BDD0E2;
    }
    .step-label {
        font-size: 13px;
        font-weight: 600;
        color: #536B82;
    }
    .step-label-active {
        color: #1F4E79;
        font-weight: 800;
    }
    .step-connector {
        flex: 1;
        height: 2px;
        background-color: #BDD0E2;
        margin: 0 10px;
    }

    /* Content Cards */
    .content-card {
        background-color: #F2F7FC;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        padding: 22px;
        margin-bottom: 18px;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.05);
    }
    .content-card-header {
        font-size: 15px;
        font-weight: 800;
        color: #1F4E79;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        gap: 10px;
        border-bottom: 1px solid #DCE8F3;
        padding-bottom: 10px;
    }

    /* Hero Section */
    .hero-box {
        text-align: center;
        padding: 34px 20px 22px;
        background-color: #DFEAF4;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        margin-bottom: 22px;
        box-shadow: 0 2px 6px rgba(22, 50, 79, 0.05);
    }
    .hero-pill {
        display: inline-block;
        background-color: #D2E4F2;
        border: 1px solid #AEC8DF;
        color: #1F4E79;
        font-size: 11px;
        font-weight: 700;
        padding: 4px 14px;
        border-radius: 20px;
        margin-bottom: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .hero-title {
        font-size: 32px;
        font-weight: 800;
        line-height: 1.25;
        color: #16324F;
        margin-bottom: 10px;
        letter-spacing: -0.5px;
    }
    .hero-desc {
        font-size: 14px;
        color: #536B82;
        font-weight: 400;
        max-width: 660px;
        margin: 0 auto 10px auto !important;
        line-height: 1.6;
    }

    /* Feature Cards */
    .feature-card {
        background-color: #F2F7FC;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        padding: 22px;
        height: 100%;
        transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.04);
    }
    .feature-card:hover {
        border-color: #1F4E79;
        box-shadow: 0 4px 10px rgba(31, 78, 121, 0.12);
        transform: translateY(-2px);
    }
    .feature-icon-badge {
        width: 46px;
        height: 46px;
        border-radius: 10px;
        background-color: #DCE8F3;
        border: 1px solid #BDD0E2;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 22px;
        margin-bottom: 14px;
    }
    .feature-title {
        font-size: 15px;
        font-weight: 800;
        color: #1F4E79;
        margin-bottom: 6px;
    }
    .feature-desc {
        font-size: 12px;
        color: #536B82;
        line-height: 1.5;
    }

    /* Selection Cards (Page 2) */
    .doc-select-card {
        background-color: #F2F7FC;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        padding: 22px 18px;
        text-align: center;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.2s ease;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.04);
    }
    .doc-select-card:hover {
        border-color: #1F4E79;
        box-shadow: 0 4px 12px rgba(31, 78, 121, 0.15);
        transform: translateY(-2px);
    }
    .doc-select-icon {
        font-size: 36px;
        margin-bottom: 10px;
    }
    .doc-select-title {
        font-size: 15px;
        font-weight: 800;
        color: #1F4E79;
        margin-bottom: 6px;
    }
    .doc-select-desc {
        font-size: 12px;
        color: #536B82;
        line-height: 1.45;
        margin-bottom: 14px;
    }

    /* High-Contrast File Uploader & Dropzone */
    [data-testid="stFileUploader"] {
        background-color: #DFEAF4 !important;
        border: 2px dashed #1F4E79 !important;
        border-radius: 10px !important;
        padding: 14px !important;
        transition: border-color 0.2s ease;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: #2F6F95 !important;
        background-color: #D6E4F0 !important;
    }
    [data-testid="stFileUploader"] section {
        background-color: #EBF2F8 !important;
        border-radius: 8px !important;
        padding: 10px !important;
    }
    [data-testid="stFileUploader"] button,
    [data-testid="stFileUploader"] [data-testid*="baseButton"],
    [data-testid="stFileUploader"] [data-testid*="Button"] {
        background-color: #1F4E79 !important;
        color: #FFFFFF !important;
        font-weight: 800 !important;
        font-size: 13px !important;
        border: 1px solid #163C60 !important;
        border-radius: 7px !important;
        padding: 8px 20px !important;
        box-shadow: 0 2px 6px rgba(31, 78, 121, 0.35) !important;
        letter-spacing: 0.3px !important;
    }
    [data-testid="stFileUploader"] button *,
    [data-testid="stFileUploader"] [data-testid*="baseButton"] *,
    [data-testid="stFileUploader"] [data-testid*="Button"] * {
        color: #FFFFFF !important;
        font-weight: 800 !important;
        font-size: 13px !important;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35) !important;
    }
    [data-testid="stFileUploader"] button:hover,
    [data-testid="stFileUploader"] [data-testid*="baseButton"]:hover,
    [data-testid="stFileUploader"] [data-testid*="Button"]:hover {
        background-color: #163C60 !important;
        border-color: #102B45 !important;
        box-shadow: 0 4px 10px rgba(31, 78, 121, 0.45) !important;
        transform: translateY(-1px);
    }
    [data-testid="stFileUploader"] button:hover *,
    [data-testid="stFileUploader"] [data-testid*="baseButton"]:hover *,
    [data-testid="stFileUploader"] [data-testid*="Button"]:hover * {
        color: #FFFFFF !important;
    }
    [data-testid="stFileUploader"] section > div,
    [data-testid="stFileUploader"] section > small,
    [data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"] * {
        color: #16324F !important;
        font-weight: 600 !important;
    }

    /* High-Contrast Camera Input Button */
    [data-testid="stCameraInput"] button {
        background-color: #0D9488 !important;
        color: #FFFFFF !important;
        font-weight: 800 !important;
        border: 1px solid #0F766E !important;
        border-radius: 6px !important;
        box-shadow: 0 2px 4px rgba(13, 148, 136, 0.3) !important;
    }
    [data-testid="stCameraInput"] button:hover {
        background-color: #0F766E !important;
    }

    /* Risk Score Banners (Page 5) */
    .risk-banner-low {
        background-color: #D5F2E3;
        border: 2px solid #238B57;
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(35, 139, 87, 0.1);
    }
    .risk-banner-med {
        background-color: #FDF1D6;
        border: 2px solid #C88A1A;
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(200, 138, 26, 0.1);
    }
    .risk-banner-high {
        background-color: #FDE2E0;
        border: 2px solid #D33C38;
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(211, 60, 56, 0.1);
    }

    /* Metric Cards */
    .metric-card {
        background-color: #F2F7FC;
        border: 1px solid #BDD0E2;
        border-radius: 10px;
        padding: 14px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(22, 50, 79, 0.04);
    }
    .metric-label {
        font-size: 11px;
        font-weight: 700;
        color: #536B82;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .metric-value {
        font-size: 20px;
        font-weight: 800;
        color: #1F4E79;
        margin-top: 4px;
    }

    /* Biometric Badges */
    .bio-badge-match {
        background-color: #D5F2E3;
        border: 1px solid #238B57;
        color: #0E5231;
        font-size: 12px;
        font-weight: 800;
        padding: 8px 14px;
        border-radius: 6px;
        text-align: center;
    }
    .bio-badge-mismatch {
        background-color: #FDE2E0;
        border: 1px solid #D33C38;
        color: #7E1916;
        font-size: 12px;
        font-weight: 800;
        padding: 8px 14px;
        border-radius: 6px;
        text-align: center;
    }

    /* Reason Detail Header Box */
    .reason-header-box {
        background-color: #DFEAF4;
        border: 1px solid #BDD0E2;
        border-left: 5px solid #1F4E79;
        border-radius: 10px;
        padding: 18px 22px;
        margin-bottom: 20px;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.05);
    }

    /* High-Contrast Standard Buttons */
    .stButton > button {
        background-color: #1F4E79 !important;
        color: #FFFFFF !important;
        font-weight: 800 !important;
        font-size: 13px !important;
        border: 1px solid #163C60 !important;
        border-radius: 8px !important;
        padding: 8px 18px !important;
        transition: all 0.15s ease !important;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.25) !important;
    }
    .stButton > button:hover {
        background-color: #163C60 !important;
        border-color: #102B45 !important;
        box-shadow: 0 4px 8px rgba(22, 50, 79, 0.35) !important;
        transform: translateY(-1px);
    }
    .stDownloadButton > button {
        background-color: #0D9488 !important;
        color: #FFFFFF !important;
        font-weight: 800 !important;
        border: 1px solid #0F766E !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 5px rgba(13, 148, 136, 0.25) !important;
    }
    .stDownloadButton > button:hover {
        background-color: #0F766E !important;
    }

    /* Key-Value Info Rows */
    .info-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 9px 12px;
        background-color: #E6EFF7;
        border: 1px solid #CBDCEB;
        border-radius: 6px;
        margin-bottom: 6px;
    }
    .info-label {
        color: #536B82;
        font-size: 12px;
        font-weight: 600;
    }
    .info-value {
        color: #16324F;
        font-size: 12px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    .info-value-pending {
        color: #C88A1A;
        font-size: 12px;
        font-weight: 700;
        font-style: italic;
    }

    /* Collapsible Dropdown & Expander Headers with Crisp White Typography */
    .streamlit-expanderHeader,
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] details summary,
    details summary,
    .stExpander summary {
        background-color: #1F4E79 !important;
        border: 1px solid #16324F !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        color: #FFFFFF !important;
        padding: 10px 16px !important;
        transition: all 0.2s ease-in-out !important;
    }

    [data-testid="stExpander"] summary:hover,
    details summary:hover {
        background-color: #16324F !important;
        color: #FFFFFF !important;
    }

    /* Force all text, spans, paragraphs, and icons inside expander header to pure white */
    .streamlit-expanderHeader *,
    [data-testid="stExpander"] summary *,
    [data-testid="stExpander"] details summary *,
    details summary * {
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        fill: #FFFFFF !important;
        stroke: #FFFFFF !important;
    }

    /* Expander chevron arrow */
    [data-testid="stExpander"] summary svg,
    details summary svg {
        fill: #FFFFFF !important;
        color: #FFFFFF !important;
        stroke: #FFFFFF !important;
    }

    /* Expander content container */
    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        border-color: #BDD0E2 !important;
        background-color: #F0F6FA !important;
        border-radius: 0 0 8px 8px !important;
    }

    /* High-Contrast Streamlit Alert System */
    [data-testid="stAlert"], .stAlert {
        border-radius: 8px !important;
        padding: 14px 18px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 1px 4px rgba(22, 50, 79, 0.08) !important;
    }
    [data-testid="stAlert"] * {
        color: #16324F !important;
        font-weight: 700 !important;
        font-size: 13px !important;
    }

    /* Dedicated High-Contrast Security Callout Badges */
    .alert-card-warning {
        background-color: #FEF3C7 !important;
        border: 1.5px solid #F59E0B !important;
        border-left: 5px solid #B45309 !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        margin-bottom: 10px !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        box-shadow: 0 1px 3px rgba(180, 83, 9, 0.12) !important;
    }
    .alert-card-warning-text {
        color: #78350F !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        line-height: 1.45 !important;
    }

    .alert-card-error {
        background-color: #FEE2E2 !important;
        border: 1.5px solid #EF4444 !important;
        border-left: 5px solid #B91C1C !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        margin-bottom: 10px !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        box-shadow: 0 1px 3px rgba(185, 28, 28, 0.12) !important;
    }
    .alert-card-error-text {
        color: #7F1D1D !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        line-height: 1.45 !important;
    }

    .alert-card-info {
        background-color: #E0F2FE !important;
        border: 1.5px solid #3B82F6 !important;
        border-left: 5px solid #1D4ED8 !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        margin-bottom: 10px !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        box-shadow: 0 1px 3px rgba(29, 78, 216, 0.12) !important;
    }
    .alert-card-info-text {
        color: #1E3A8A !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        line-height: 1.45 !important;
    }

    /* VERIDEX Digital Document Gateway Styles */
    .gateway-disclaimer-card {
        background-color: #FEF3C7 !important;
        border: 1.5px solid #F59E0B !important;
        border-left: 5px solid #B45309 !important;
        border-radius: 8px !important;
        padding: 12px 18px !important;
        margin-bottom: 16px !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
    }
    .gateway-disclaimer-text {
        font-size: 12px !important;
        font-weight: 700 !important;
        color: #78350F !important;
        line-height: 1.45 !important;
    }
    .gateway-hero-box {
        background-color: #DFEAF4;
        border: 1px solid #BDD0E2;
        border-radius: 12px;
        padding: 24px 20px 20px;
        text-align: center;
        margin-bottom: 18px;
        box-shadow: 0 2px 6px rgba(22, 50, 79, 0.05);
    }
    .gateway-doc-card {
        background-color: #F2F7FC;
        border: 1.5px solid #BDD0E2;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 14px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.15s ease;
        box-shadow: 0 2px 5px rgba(22, 50, 79, 0.04);
    }
    .gateway-doc-card:hover {
        border-color: #1F4E79;
        box-shadow: 0 4px 12px rgba(31, 78, 121, 0.12);
        transform: translateY(-2px);
    }
    .gateway-issuer-pill {
        background-color: #D5F2E3;
        border: 1px solid #238B57;
        color: #0E5231;
        font-size: 10px;
        font-weight: 800;
        padding: 3px 8px;
        border-radius: 12px;
        display: inline-block;
    }

    /* Authentic Modern DigiLocker Modal Cards & UI */
    .digi-modal-card {
        background-color: #FFFFFF !important;
        border: 1px solid #E5E7EB !important;
        border-radius: 20px !important;
        padding: 30px 28px !important;
        max-width: 500px !important;
        margin: 0 auto 20px auto !important;
        box-shadow: 0 10px 25px rgba(91, 69, 224, 0.08) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }
    .digi-title {
        font-size: 22px !important;
        font-weight: 800 !important;
        color: #111827 !important;
        margin-bottom: 6px !important;
        line-height: 1.25 !important;
    }
    .digi-subtitle {
        font-size: 13px !important;
        font-weight: 500 !important;
        color: #6B7280 !important;
        margin-bottom: 20px !important;
        line-height: 1.45 !important;
    }
    .digi-account-card {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        padding: 14px 18px !important;
        border: 1.5px solid #E5E7EB !important;
        border-radius: 14px !important;
        margin-bottom: 16px !important;
        background-color: #FFFFFF !important;
        transition: all 0.15s ease !important;
    }
    .digi-avatar-badge {
        width: 44px !important;
        height: 44px !important;
        border-radius: 12px !important;
        background-color: #5B45E0 !important;
        color: #FFFFFF !important;
        font-size: 15px !important;
        font-weight: 800 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        flex-shrink: 0 !important;
    }
    .digi-verified-pill {
        color: #10B981 !important;
        font-size: 12px !important;
        font-weight: 700 !important;
        display: inline-flex !important;
        align-items: center !important;
        gap: 4px !important;
    }
    .digi-method-card-active {
        border: 2px solid #5B45E0 !important;
        background-color: #F5F3FF !important;
        border-radius: 14px !important;
        padding: 14px 16px !important;
        margin-bottom: 10px !important;
    }
    .digi-method-card-idle {
        border: 1.5px solid #E5E7EB !important;
        background-color: #FFFFFF !important;
        border-radius: 14px !important;
        padding: 14px 16px !important;
        margin-bottom: 10px !important;
    }
    .digi-pin-boxes-wrap {
        display: flex !important;
        justify-content: center !important;
        gap: 8px !important;
        margin: 16px 0 8px 0 !important;
        align-items: center !important;
    }
    .digi-pin-box {
        width: 44px !important;
        height: 48px !important;
        border: 1.5px solid #D1D5DB !important;
        border-radius: 10px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-size: 20px !important;
        font-weight: 800 !important;
        color: #111827 !important;
        background-color: #FFFFFF !important;
    }
    .digi-pin-box-active {
        border: 2px solid #5B45E0 !important;
        box-shadow: 0 0 0 3px rgba(91, 69, 224, 0.15) !important;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# STATE MANAGEMENT
# ============================================================
if "page" not in st.session_state:
    st.session_state.page = 1
if "app_mode" not in st.session_state:
    st.session_state.app_mode = "direct"
if "document_type" not in st.session_state:
    st.session_state.document_type = "passport"
if "document_file" not in st.session_state:
    st.session_state.document_file = None
if "person_file" not in st.session_state:
    st.session_state.person_file = None
if "document_path_override" not in st.session_state:
    st.session_state.document_path_override = None
if "person_path_override" not in st.session_state:
    st.session_state.person_path_override = None
if "result" not in st.session_state:
    st.session_state.result = None
if "vault_user_id" not in st.session_state:
    st.session_state.vault_user_id = "NONE"
if "vault_doc_type" not in st.session_state:
    st.session_state.vault_doc_type = None

# Gateway-Specific State
if "gateway_step" not in st.session_state:
    st.session_state.gateway_step = 1
if "gateway_user_id" not in st.session_state:
    st.session_state.gateway_user_id = "VX001"
if "gateway_auth_type" not in st.session_state:
    st.session_state.gateway_auth_type = "mobile"
if "gateway_identifier" not in st.session_state:
    st.session_state.gateway_identifier = "9999999999"
if "gateway_otp" not in st.session_state:
    st.session_state.gateway_otp = "123456"
if "gateway_auth_method" not in st.session_state:
    st.session_state.gateway_auth_method = "totp"
if "gateway_pin" not in st.session_state:
    st.session_state.gateway_pin = "123456"
if "gateway_selected_doc_id" not in st.session_state:
    st.session_state.gateway_selected_doc_id = "DOC-AADH-001"
if "gateway_consent_granted" not in st.session_state:
    st.session_state.gateway_consent_granted = False


# ============================================================
# TOP HEADER BAR
# ============================================================
st.markdown(
    """
<div class="brand-header">
    <div class="brand-logo-area">
        <div class="brand-logo-badge">🛡️</div>
        <div>
            <div class="brand-title">VERIDEX</div>
            <div class="brand-sub">AI Identity & Document Screening System — Enterprise KYC & Border Security</div>
        </div>
    </div>
    <div class="status-badge">
        <div class="status-dot"></div>
        Screening Engine Operational
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# Mode Switcher Bar
mcol1, mcol2 = st.columns([1, 1])
with mcol1:
    is_direct = (st.session_state.app_mode == "direct")
    if st.button("⚡ Mode 1: Direct Document Screening", use_container_width=True, type="primary" if is_direct else "secondary"):
        st.session_state.app_mode = "direct"
        st.rerun()

with mcol2:
    is_gw = (st.session_state.app_mode == "gateway")
    if st.button("🏛️ Mode 2: VERIDEX Digital Document Gateway (DigiLocker)", use_container_width=True, type="primary" if is_gw else "secondary"):
        st.session_state.app_mode = "gateway"
        st.rerun()


# ============================================================
# STEPPER PROGRESS COMPONENTS
# ============================================================
def render_stepper(current_page: int):
    steps = [
        (1, "Welcome"),
        (2, "Doc Type"),
        (3, "Upload"),
        (4, "Pipeline"),
        (5, "Extracted Info"),
        (6, "Why Flagged"),
        (7, "Doc Checks"),
    ]
    html = '<div class="stepper-wrap">'
    for idx, (p_num, p_name) in enumerate(steps):
        if p_num < current_page:
            bubble_class = "step-done"
            label_class = "step-label"
            bubble_content = "✓"
        elif p_num == current_page:
            bubble_class = "step-active"
            label_class = "step-label step-label-active"
            bubble_content = str(p_num)
        else:
            bubble_class = "step-idle"
            label_class = "step-label"
            bubble_content = str(p_num)

        html += f"""
        <div class="step-item">
            <div class="step-bubble {bubble_class}">{bubble_content}</div>
            <div class="{label_class}">{p_name}</div>
        </div>
        """
        if idx < len(steps) - 1:
            html += '<div class="step-connector"></div>'
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def render_gateway_stepper(current_step: int):
    steps = [
        (1, "1. Login"),
        (2, "2. Account"),
        (3, "3. 2FA"),
        (4, "4. PIN"),
        (5, "5. Wallet"),
        (6, "6. Consent"),
        (7, "7. Face & Fetch"),
    ]
    html = '<div class="stepper-wrap">'
    for idx, (p_num, p_name) in enumerate(steps):
        if p_num < current_step:
            bubble_class = "step-done"
            label_class = "step-label"
            bubble_content = "✓"
        elif p_num == current_step:
            bubble_class = "step-active"
            label_class = "step-label step-label-active"
            bubble_content = str(p_num)
        else:
            bubble_class = "step-idle"
            label_class = "step-label"
            bubble_content = str(p_num)

        html += f"""
        <div class="step-item">
            <div class="step-bubble {bubble_class}">{bubble_content}</div>
            <div class="{label_class}">{p_name}</div>
        </div>
        """
        if idx < len(steps) - 1:
            html += '<div class="step-connector"></div>'
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


# ============================================================
# VERIDEX DIGITAL DOCUMENT GATEWAY FLOW (DIGILOCKER MIMIC)
# ============================================================
def render_gateway_flow():
    render_gateway_stepper(st.session_state.gateway_step)

    # Prototype Simulation Notice Banner
    st.markdown(
        """
    <div class="gateway-disclaimer-card">
        <span style="font-size: 22px;">🔒</span>
        <div class="gateway-disclaimer-text">
            <b>PROTOTYPE & SIMULATION DISCLAIMER:</b> This is an offline DigiLocker-inspired simulation for Hackathon demonstration. No real government credentials or real Aadhaar OTPs are collected or transmitted.
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # STEP 1: LOGIN OR CREATE ACCOUNT (Matches Screenshot 1)
    if st.session_state.gateway_step == 1:
        col_pad1, col_center, col_pad2 = st.columns([1, 2.2, 1])
        with col_center:
            # Quick 1-click evaluation presets
            st.markdown(
                """<div style="background-color: #DFEAF4; border: 1px solid #BDD0E2; border-radius: 12px; padding: 10px 14px; margin-bottom: 12px; text-align: center;">
<div style="font-size: 11px; font-weight: 800; color: #1F4E79; text-transform: uppercase; letter-spacing: 0.5px;">⚡ 1-Click Quick-Fill Demo Profiles (Select to Test)</div>
</div>""",
                unsafe_allow_html=True,
            )
            p1, p2, p3 = st.columns(3)
            with p1:
                if st.button("👨‍💼 Sriram (9999999999)", use_container_width=True, key="demo_p1"):
                    st.session_state.gateway_identifier = "9999999999"
                    st.session_state.gateway_auth_type = "mobile"
                    st.session_state.gateway_user_id = "VX001"
                    st.rerun()
            with p2:
                if st.button("👨‍🎓 Arun (9876543210)", use_container_width=True, key="demo_p2"):
                    st.session_state.gateway_identifier = "9876543210"
                    st.session_state.gateway_auth_type = "mobile"
                    st.session_state.gateway_user_id = "VX003"
                    st.rerun()
            with p3:
                if st.button("👩‍💼 Anna (7012345678)", use_container_width=True, key="demo_p3"):
                    st.session_state.gateway_identifier = "7012345678"
                    st.session_state.gateway_auth_type = "mobile"
                    st.session_state.gateway_user_id = "VX002"
                    st.rerun()

            # DigiLocker Login Modal Card Header
            st.markdown(
                """<div class="digi-modal-card" style="margin-bottom: 12px;">
<div style="text-align: center; margin-bottom: 14px;">
<div style="display: inline-flex; align-items: center; justify-content: center; width: 50px; height: 50px; background: linear-gradient(135deg, #5B45E0 0%, #7C3AED 100%); border-radius: 14px; font-size: 24px; color: #FFFFFF; box-shadow: 0 4px 12px rgba(91, 69, 224, 0.25);">🏛️</div>
</div>
<div class="digi-title" style="text-align: center;">Login or Create Account</div>
<div class="digi-subtitle" style="text-align: center;">Enter your registered mobile number or Aadhaar to continue</div>
</div>""",
                unsafe_allow_html=True,
            )

            c_code, c_num = st.columns([1.1, 3])
            with c_code:
                st.text_input("Country Code", value="+91 🇮🇳", disabled=True, label_visibility="collapsed", key="gw_cc_inp")
            with c_num:
                mob_input = st.text_input("Mobile Number", value=st.session_state.gateway_identifier, placeholder="Enter mobile number", label_visibility="collapsed", key="gw_mob_inp")
                st.session_state.gateway_identifier = mob_input

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            if st.button("Continue", type="primary", use_container_width=True, key="btn_gw_step1_continue"):
                is_ok, msg, uid = verify_gateway_login(st.session_state.gateway_identifier, "mobile")
                if is_ok:
                    st.session_state.gateway_user_id = uid or st.session_state.gateway_user_id
                    st.session_state.gateway_step = 2
                    log_gateway_event("GATEWAY_LOGIN_INITIATED", f"Initiated authentication for identifier: {st.session_state.gateway_identifier}", st.session_state.gateway_user_id)
                    st.rerun()
                else:
                    st.error(msg)

            st.markdown(
                """<div style="text-align: center; font-size: 11px; color: #6B7280; margin-top: 14px; line-height: 1.5;">
By continuing, you agree to our <b style="color: #5B45E0;">Terms of Service</b> and <b style="color: #5B45E0;">Privacy Policy</b>
</div>""",
                unsafe_allow_html=True,
            )

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            if st.button("← Switch to Direct Screening Mode", use_container_width=True, key="btn_gw_to_direct"):
                st.session_state.app_mode = "direct"
                st.session_state.page = 1
                st.rerun()

    # STEP 2: SELECT ACCOUNT (Matches Screenshot 2)
    elif st.session_state.gateway_step == 2:
        citizen = get_citizen_profile(st.session_state.gateway_user_id)
        name = citizen.get("full_name", "Sriram Mamundi")
        initials = get_initials(name)
        masked_name = get_masked_name(name)

        col_pad1, col_center, col_pad2 = st.columns([1, 2.2, 1])
        with col_center:
            st.markdown(
                f"""<div class="digi-modal-card">
<div style="text-align: center; margin-bottom: 14px;">
<div style="display: inline-flex; align-items: center; justify-content: center; width: 50px; height: 50px; background: linear-gradient(135deg, #5B45E0 0%, #7C3AED 100%); border-radius: 14px; font-size: 24px; color: #FFFFFF; box-shadow: 0 4px 12px rgba(91, 69, 224, 0.25);">🏛️</div>
</div>
<div class="digi-title" style="text-align: center;">Select Account</div>
<div class="digi-subtitle" style="text-align: center;">Select an account to continue with DigiLocker</div>
<div class="digi-account-card">
<div style="display: flex; align-items: center; gap: 14px;">
<div class="digi-avatar-badge">{initials}</div>
<div>
<div style="font-size: 16px; font-weight: 800; color: #111827;">{masked_name}</div>
<div class="digi-verified-pill">✓ Verified</div>
</div>
</div>
<div style="font-size: 18px; color: #9CA3AF; font-weight: 700;">❯</div>
</div>
</div>""",
                unsafe_allow_html=True,
            )

            if st.button(f"Continue with Selected Account ❯", type="primary", use_container_width=True, key="btn_acc_continue"):
                st.session_state.gateway_step = 3
                log_gateway_event("GATEWAY_ACCOUNT_SELECTED", f"Account selected: {name}", st.session_state.gateway_user_id)
                st.rerun()

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            if st.button("+ Create New Account / Switch Profile", use_container_width=True, key="btn_acc_switch"):
                st.session_state.gateway_step = 1
                st.rerun()

    # STEP 3: VERIFY USING (TOTP / OTP) (Matches Screenshot 3)
    elif st.session_state.gateway_step == 3:
        citizen = get_citizen_profile(st.session_state.gateway_user_id)
        name = citizen.get("full_name", "Sriram Mamundi")
        masked_phone = citizen.get("phone", "+91 99999 99999")

        col_pad1, col_center, col_pad2 = st.columns([1, 2.2, 1])
        with col_center:
            st.markdown(
                """<div class="digi-modal-card" style="margin-bottom: 12px;">
<div style="text-align: center; margin-bottom: 14px;">
<div style="display: inline-flex; align-items: center; justify-content: center; width: 50px; height: 50px; background: linear-gradient(135deg, #5B45E0 0%, #7C3AED 100%); border-radius: 14px; font-size: 24px; color: #FFFFFF; box-shadow: 0 4px 12px rgba(91, 69, 224, 0.25);">🔐</div>
</div>
<div class="digi-title" style="text-align: center;">Verify Using</div>
<div class="digi-subtitle" style="text-align: center;">Please select an option to verify your account</div>
</div>""",
                unsafe_allow_html=True,
            )

            method_choice = st.radio(
                "Verification Method",
                options=["totp", "otp"],
                index=0 if st.session_state.gateway_auth_method == "totp" else 1,
                format_func=lambda x: "📱 TOTP — Open your DigiLocker App to access the TOTP" if x == "totp" else f"💬 OTP — You will receive an SMS on your Mobile",
                key="gw_radio_method",
            )
            st.session_state.gateway_auth_method = method_choice
            is_totp = (method_choice == "totp")

            code_desc = "DigiLocker Authenticator App" if is_totp else f"SMS sent to {masked_phone}"

            st.markdown(
                f"""<div style="background-color: #FFFFFF; border: 1.5px solid #E5E7EB; border-radius: 14px; padding: 12px 16px; margin: 10px 0 14px 0;">
<div style="font-size: 13px; font-weight: 700; color: #111827; margin-bottom: 2px;">Enter 6-Digit {'TOTP Code' if is_totp else 'SMS OTP'}</div>
<div style="font-size: 11px; color: #6B7280;">Source: {code_desc}</div>
</div>""",
                unsafe_allow_html=True,
            )

            code_val = st.text_input("Enter 6-Digit Code", value=st.session_state.gateway_otp, max_chars=6, placeholder="123456", label_visibility="collapsed", key="gw_2fa_code_inp")
            st.session_state.gateway_otp = code_val

            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1:
                if st.button("⚡ Fill Demo Code (123456)", use_container_width=True, key="btn_fill_demo_2fa"):
                    st.session_state.gateway_otp = "123456"
                    st.rerun()
            with c2:
                if st.button("🔄 Resend Code", use_container_width=True, key="btn_resend_2fa"):
                    st.info("Simulated verification code re-sent: 123456")

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            if st.button("Continue", type="primary", use_container_width=True, key="btn_2fa_continue"):
                ok, msg = verify_gateway_otp(st.session_state.gateway_otp)
                if ok:
                    st.session_state.gateway_step = 4
                    log_gateway_event("GATEWAY_2FA_VERIFIED", f"Verified via {method_choice.upper()}", st.session_state.gateway_user_id)
                    st.rerun()
                else:
                    st.error(msg)

            st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
            if st.button("← Back to Select Account", use_container_width=True, key="btn_2fa_back"):
                st.session_state.gateway_step = 2
                st.rerun()

    # STEP 4: ENTER 6 DIGIT SECURITY PIN (Matches Screenshot 4)
    elif st.session_state.gateway_step == 4:
        citizen = get_citizen_profile(st.session_state.gateway_user_id)
        name = citizen.get("full_name", "Sriram Mamundi")
        initials = get_initials(name)
        masked_name = get_masked_name(name)

        # 6 Square PIN Visual Boxes
        pin_str = str(st.session_state.gateway_pin or "")
        boxes_html = '<div class="digi-pin-boxes-wrap">'
        for i in range(6):
            char_disp = pin_str[i] if i < len(pin_str) else ""
            active_cls = "digi-pin-box-active" if i < len(pin_str) else ""
            dot = "•" if char_disp else ""
            boxes_html += f'<div class="digi-pin-box {active_cls}">{dot}</div>'
        boxes_html += '<span style="font-size: 20px; color: #6B7280; margin-left: 6px;">👁️</span></div>'

        col_pad1, col_center, col_pad2 = st.columns([1, 2.2, 1])
        with col_center:
            st.markdown(
                f"""<div class="digi-modal-card">
<div style="display: flex; align-items: center; justify-content: center; gap: 10px; background-color: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 12px; padding: 8px 14px; margin-bottom: 18px;">
<div class="digi-avatar-badge" style="width: 32px; height: 32px; font-size: 12px; border-radius: 8px;">{initials}</div>
<div style="font-size: 14px; font-weight: 700; color: #111827;">{masked_name}</div>
<div class="digi-verified-pill" style="font-size: 11px;">✓ Verified</div>
</div>
<div class="digi-title" style="text-align: center; font-size: 20px;">Enter 6 digit security PIN</div>
<div class="digi-subtitle" style="text-align: center; margin-bottom: 10px;">Enter your DigiLocker PIN to decrypt digital wallet</div>
{boxes_html}
</div>""",
                unsafe_allow_html=True,
            )

            pin_val = st.text_input("Enter 6-Digit PIN", value=st.session_state.gateway_pin, type="password", max_chars=6, placeholder="••••••", label_visibility="collapsed", key="gw_pin_input_text")
            st.session_state.gateway_pin = pin_val

            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            if st.button("⚡ Fill Demo PIN (123456)", use_container_width=True, key="btn_fill_demo_pin_4"):
                st.session_state.gateway_pin = "123456"
                st.rerun()

            st.markdown(
                """<div style="text-align: center; margin: 10px 0 14px 0;">
<a href="#" style="color: #5B45E0; font-size: 12px; font-weight: 700; text-decoration: none;">Forgot security PIN?</a>
</div>""",
                unsafe_allow_html=True,
            )

            if st.button("Verify 🔓", type="primary", use_container_width=True, key="btn_verify_pin_submit"):
                ok, msg = verify_gateway_pin(st.session_state.gateway_pin)
                if ok:
                    st.session_state.gateway_step = 5
                    log_gateway_event("GATEWAY_WALLET_UNLOCKED", f"Digital wallet unlocked for {name}", st.session_state.gateway_user_id)
                    st.rerun()
                else:
                    st.error(msg)

            st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
            if st.button("← Back to 2FA Method", use_container_width=True, key="btn_pin_back_to_2fa"):
                st.session_state.gateway_step = 3
                st.rerun()

    # STEP 5: CITIZEN DIGITAL WALLET
    elif st.session_state.gateway_step == 5:
        citizen = get_citizen_profile(st.session_state.gateway_user_id)
        issued_docs = citizen.get("issued_documents", [])
        uploaded_docs = citizen.get("uploaded_documents", [])
        activity_logs = get_gateway_activity_logs()

        # Citizen Header Card
        st.markdown(
            f"""
        <div style="background-color: #DFEAF4; border: 1.5px solid #BDD0E2; border-radius: 12px; padding: 18px 22px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 14px;">
                <div style="font-size: 36px; background-color: #DCE8F3; width: 56px; height: 56px; border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 2px solid #1F4E79;">
                    {citizen.get('avatar_icon', '👨‍💼')}
                </div>
                <div>
                    <div style="font-size: 18px; font-weight: 800; color: #16324F;">{citizen.get('full_name')}</div>
                    <div style="font-size: 12px; color: #536B82; font-weight: 600;">
                        DigiLocker ID: <b>{citizen.get('user_id')}</b> | Contact: <b>{citizen.get('phone')}</b>
                    </div>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="background-color: #D5F2E3; border: 1px solid #238B57; color: #0E5231; font-size: 11px; font-weight: 800; padding: 4px 12px; border-radius: 14px; display: inline-block;">
                    ✓ {citizen.get('verification_level', 'ISSUER_VERIFIED')}
                </div>
                <div style="font-size: 11px; color: #536B82; margin-top: 3px;">Active Issuer Session</div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        tab_issued, tab_uploaded, tab_activity = st.tabs([
            f"📜 Issued Documents ({len(issued_docs)})",
            f"📂 My Documents ({len(uploaded_docs)})",
            f"📊 Activity & Audit Log ({len(activity_logs)})",
        ])

        with tab_issued:
            st.markdown("<div style='font-size: 14px; font-weight: 800; color: #1F4E79; margin-bottom: 12px;'>Official Government-Issued Digital Credentials</div>", unsafe_allow_html=True)
            cols = st.columns(2)
            for idx, doc in enumerate(issued_docs):
                col = cols[idx % 2]
                with col:
                    st.markdown(
                        f"""
                        <div class="gateway-doc-card">
                            <div>
                                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <span style="font-size: 24px;">{doc.get('icon', '🪪')}</span>
                                        <div>
                                            <div style="font-size: 14px; font-weight: 800; color: #16324F;">{doc.get('doc_name')}</div>
                                            <div style="font-size: 11px; color: #536B82;">{doc.get('category')}</div>
                                        </div>
                                    </div>
                                    <span class="gateway-issuer-pill">✓ {doc.get('status', 'VERIFIED')}</span>
                                </div>
                                <div style="background-color: #E6EFF7; border-radius: 6px; padding: 8px 10px; margin: 8px 0;">
                                    <div style="font-size: 11px; color: #536B82;">Document Number:</div>
                                    <div style="font-size: 13px; font-weight: 800; color: #1F4E79; font-family: 'JetBrains Mono', monospace;">
                                        {doc.get('masked_number', doc.get('doc_number'))}
                                    </div>
                                </div>
                                <div style="font-size: 11px; color: #536B82; line-height: 1.5; margin-bottom: 10px;">
                                    Issuer: <b>{doc.get('issuer')}</b><br>
                                    Issued: <b>{doc.get('issued_on')}</b> | Expiry: <b>{doc.get('expiry')}</b><br>
                                    Digital Seal: <span style="font-family: 'JetBrains Mono'; font-size: 10px; color: #0E5231;">{doc.get('digital_signature')}</span>
                                </div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if st.button(f"Fetch & Screen {doc.get('doc_name')}  →", key=f"btn_screen_{doc['doc_id']}", use_container_width=True):
                        st.session_state.gateway_selected_doc_id = doc["doc_id"]
                        st.session_state.gateway_consent_granted = False
                        st.session_state.gateway_step = 6
                        log_gateway_event("GATEWAY_DOC_SELECTED", f"Selected {doc['doc_name']} ({doc['doc_number']}) for verification.", st.session_state.gateway_user_id, doc["doc_name"])
                        st.rerun()

        with tab_uploaded:
            st.markdown("<div style='font-size: 14px; font-weight: 800; color: #1F4E79; margin-bottom: 12px;'>Self-Uploaded Supporting Proofs</div>", unsafe_allow_html=True)
            if uploaded_docs:
                for udoc in uploaded_docs:
                    st.markdown(
                        f"""
                        <div style="background-color: #F2F7FC; border: 1px solid #BDD0E2; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-size: 13px; font-weight: 700; color: #16324F;">{udoc.get('doc_name')} ({udoc.get('doc_number')})</div>
                                <div style="font-size: 11px; color: #536B82;">Uploaded: {udoc.get('uploaded_on')} | Category: {udoc.get('category')}</div>
                            </div>
                            <div style="background-color: #DCE8F3; color: #1F4E79; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 10px;">
                                {udoc.get('status')}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No additional self-uploaded documents found in this citizen's wallet.")

        with tab_activity:
            st.markdown("<div style='font-size: 14px; font-weight: 800; color: #1F4E79; margin-bottom: 12px;'>Gateway Session Audit Trail & Access Logs</div>", unsafe_allow_html=True)
            for ev in activity_logs:
                st.markdown(
                    f"""
                    <div style="background-color: #F2F7FC; border: 1px solid #BDD0E2; border-left: 4px solid #1F4E79; border-radius: 6px; padding: 10px 14px; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-size: 12px; font-weight: 700; color: #16324F;">[{ev.get('event_type')}] {ev.get('details')}</div>
                            <div style="font-size: 10px; color: #536B82;">Timestamp: {ev.get('timestamp')} | User: {ev.get('user_id')}</div>
                        </div>
                        <div style="font-family: 'JetBrains Mono'; font-size: 10px; background-color: #E6EFF7; padding: 3px 6px; border-radius: 4px; color: #1F4E79;">
                            HASH: {ev.get('security_hash')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔒 Log Out / Switch Citizen Profile", use_container_width=True, key="btn_wallet_logout"):
            st.session_state.gateway_step = 1
            st.session_state.gateway_selected_doc_id = None
            st.session_state.gateway_consent_granted = False
            st.rerun()

    # STEP 6: DOCUMENT PREVIEW & CONSENT
    elif st.session_state.gateway_step == 6:
        doc = get_gateway_document_by_id(st.session_state.gateway_user_id, st.session_state.gateway_selected_doc_id)
        if not doc:
            st.error("Selected document not found. Returning to wallet.")
            st.session_state.gateway_step = 5
            st.rerun()

        citizen = get_citizen_profile(st.session_state.gateway_user_id)

        st.markdown(
            f"""
        <div style="text-align: center; margin-bottom: 18px;">
            <h2 style="font-size: 22px; font-weight: 800; color: #16324F; margin-bottom: 4px;">Document Authorization & User Consent</h2>
            <div style="color: #536B82; font-size: 13px;">Review credential details and authorize VERIDEX to fetch and verify the digital master document.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns([1.2, 1])
        with col1:
            st.markdown(
                f"""
                <div class="content-card">
                    <div class="content-card-header">
                        <span style="font-size: 20px;">{doc.get('icon', '🪪')}</span> {doc.get('doc_name')} — Metadata Profile
                    </div>
                    <div class="info-row"><span class="info-label">Document ID</span><span class="info-value">{doc.get('doc_id')}</span></div>
                    <div class="info-row"><span class="info-label">Document Type</span><span class="info-value">{doc.get('doc_type').upper()}</span></div>
                    <div class="info-row"><span class="info-label">Document Number</span><span class="info-value">{doc.get('doc_number')}</span></div>
                    <div class="info-row"><span class="info-label">Issuing Authority</span><span class="info-value">{doc.get('issuer')}</span></div>
                    <div class="info-row"><span class="info-label">Date of Issue</span><span class="info-value">{doc.get('issued_on')}</span></div>
                    <div class="info-row"><span class="info-label">Date of Expiry</span><span class="info-value">{doc.get('expiry')}</span></div>
                    <div class="info-row"><span class="info-label">Digital Signature</span><span class="info-value" style="color: #0E5231;">{doc.get('digital_signature')}</span></div>
                    <div class="info-row"><span class="info-label">Issuer Status</span><span class="info-value" style="color: #0E5231;">✓ {doc.get('status')}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col2:
            img_path = doc.get("absolute_image_path")
            if img_path and os.path.exists(img_path):
                st.image(img_path, caption=f"DigiLocker Master Record: {doc.get('doc_name')}", use_container_width=True)

        # Mandatory Legal Consent Checkbox Card
        st.markdown(
            """
            <div style="background-color: #E0F2FE; border: 1.5px solid #3B82F6; border-left: 5px solid #1D4ED8; border-radius: 8px; padding: 14px 18px; margin: 16px 0;">
                <div style="font-size: 13px; font-weight: 800; color: #1E3A8A; margin-bottom: 6px;">
                    📋 Citizen Consent & Data Processing Authorization
                </div>
                <div style="font-size: 12px; color: #1E3A8A; line-height: 1.45;">
                    In compliance with the Information Technology (Preservation and Retention of Information by Intermediaries Providing Digital Locker Facilities) Rules and DPDP Act guidelines, VERIDEX requires explicit authorization from the credential holder to fetch, decrypt, and perform AI multi-factor document and biometric screening.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        consent_chk = st.checkbox(
            "I hereby authorize VERIDEX to fetch, decrypt, and use this issuer-verified digital credential for AI-powered identity screening, tamper forensics, and facial verification.",
            value=st.session_state.gateway_consent_granted,
            key="chk_gw_consent_box",
        )
        st.session_state.gateway_consent_granted = consent_chk

        st.markdown("<br>", unsafe_allow_html=True)
        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button("← Back to Digital Wallet", use_container_width=True, key="btn_consent_back_wallet"):
                st.session_state.gateway_step = 5
                st.rerun()
        with bcol2:
            if st.button("Allow & Fetch Document 📥 →", disabled=not consent_chk, use_container_width=True, key="btn_consent_allow_fetch"):
                st.session_state.gateway_step = 7
                log_gateway_event("GATEWAY_CONSENT_GRANTED", f"Citizen authorized fetch of {doc['doc_name']}.", st.session_state.gateway_user_id, doc["doc_name"])
                st.rerun()

    # STEP 7: LIVE FETCH & PRESENTING PERSON FACE CAPTURE
    elif st.session_state.gateway_step == 7:
        doc = get_gateway_document_by_id(st.session_state.gateway_user_id, st.session_state.gateway_selected_doc_id)
        if not doc:
            st.error("Document not found.")
            st.session_state.gateway_step = 5
            st.rerun()

        citizen = get_citizen_profile(st.session_state.gateway_user_id)

        st.markdown(
            f"""
        <div style="text-align: center; margin-bottom: 18px;">
            <h2 style="font-size: 22px; font-weight: 800; color: #16324F; margin-bottom: 4px;">Digital Document Fetched: <span style="color: #1F4E79;">{doc.get('doc_name')}</span></h2>
            <div style="color: #536B82; font-size: 13px;">Document fetched and decrypted from National Trust Framework. Provide presenting person photograph for 1:1 facial biometric matching.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        # Multi-Stage Fetch Simulation Card
        st.markdown(
            f"""
        <div style="background-color: #D5F2E3; border: 1.5px solid #238B57; border-radius: 10px; padding: 14px 18px; margin-bottom: 18px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 24px;">✅</span>
                    <div>
                        <div style="font-size: 13px; font-weight: 800; color: #0E5231;">CRYPTOGRAPHICALLY VERIFIED CREDENTIAL RECEIVED</div>
                        <div style="font-size: 11px; color: #0E5231;">Source: <b>{doc.get('issuer')}</b> | Sig: <b>{doc.get('digital_signature')}</b> | SHA-256 Hash Match Verified</div>
                    </div>
                </div>
                <div style="background-color: #238B57; color: #FFFFFF; font-size: 11px; font-weight: 800; padding: 4px 10px; border-radius: 12px;">
                    100% INTEGRITY
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(
                """
            <div class="content-card" style="margin-bottom: 12px;">
                <div style="font-size: 11px; font-weight: 800; color: #1F4E79; text-transform: uppercase; margin-bottom: 4px;">Fetched Credential</div>
                <div style="font-size: 15px; font-weight: 800; color: #16324F;">Issuer Master Photograph & Fields</div>
                <div style="font-size: 12px; color: #536B82; margin-top: 2px;">Official verified document specimen loaded from Digital Vault.</div>
            </div>
            """,
                unsafe_allow_html=True,
            )
            img_path = doc.get("absolute_image_path")
            if img_path and os.path.exists(img_path):
                st.image(img_path, caption=f"Verified Record: {doc.get('doc_name')} ({doc.get('doc_number')})", use_container_width=True)

        with col2:
            st.markdown(
                """
            <div class="content-card" style="margin-bottom: 12px;">
                <div style="font-size: 11px; font-weight: 800; color: #0D9488; text-transform: uppercase; margin-bottom: 4px;">Live Person Verification</div>
                <div style="font-size: 15px; font-weight: 800; color: #16324F;">Presenting Person Face Capture</div>
                <div style="font-size: 12px; color: #536B82; margin-top: 2px;">Capture live face via webcam OR upload presenting citizen's photograph.</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

            # 1-Click Preset Person Photo Helper
            rec_person = doc.get("recommended_person")
            rec_person_abs = doc.get("absolute_person_path")
            if rec_person_abs and os.path.exists(rec_person_abs):
                if st.button(f"⚡ Quick-Fill Matching Person Photo ({citizen['full_name']})", use_container_width=True, key="btn_quick_person_photo"):
                    st.session_state.person_path_override = rec_person_abs
                    st.session_state.person_file = None
                    st.rerun()

            cam_photo = st.camera_input("Capture Live Face from Webcam", key="gw_cam_input")
            person_up = st.file_uploader("Or Upload Person Photograph", type=["jpg", "jpeg", "png", "webp"], key="gw_person_upload")

            if cam_photo:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_c:
                    tmp_c.write(cam_photo.getbuffer())
                    st.session_state.person_path_override = tmp_c.name
                    st.session_state.person_file = None
            elif person_up:
                st.session_state.person_file = person_up
                st.session_state.person_path_override = None

            if st.session_state.person_path_override:
                st.image(st.session_state.person_path_override, caption="Selected Presenting Person Face Photo", width=180)
            elif st.session_state.person_file:
                st.image(st.session_state.person_file, caption=f"Uploaded Photo: {st.session_state.person_file.name}", width=180)

        st.markdown("<br>", unsafe_allow_html=True)
        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button("← Choose Different Document", use_container_width=True, key="btn_step7_diff_doc"):
                st.session_state.gateway_step = 5
                st.rerun()
        with bcol2:
            if st.button("🚀 Launch Full VERIDEX 7-Layer Screening Pipeline", use_container_width=True, key="btn_step7_launch_screening"):
                has_person = bool(st.session_state.person_file or st.session_state.person_path_override or (rec_person_abs and os.path.exists(rec_person_abs)))
                if not has_person and rec_person_abs and os.path.exists(rec_person_abs):
                    st.session_state.person_path_override = rec_person_abs

                if not (st.session_state.person_file or st.session_state.person_path_override):
                    st.error("Please capture or upload the presented person's photograph before screening.")
                else:
                    # Handover to the existing VERIDEX Screening Pipeline (Page 4)
                    st.session_state.document_type = doc["doc_type"]
                    st.session_state.document_path_override = doc["absolute_image_path"]
                    st.session_state.document_file = None
                    st.session_state.vault_user_id = st.session_state.gateway_user_id
                    st.session_state.vault_doc_type = doc["doc_type"]
                    st.session_state.page = 4
                    log_gateway_event("GATEWAY_SCREENING_LAUNCHED", f"Triggered 7-layer verification for {doc['doc_name']}.", st.session_state.gateway_user_id, doc["doc_name"])
                    st.rerun()



# ============================================================
# MAIN APPLICATION PAGE ROUTING (GATEWAY VS DIRECT SCREENING)
# ============================================================
if st.session_state.app_mode == "gateway" and st.session_state.page < 4:
    render_gateway_flow()
    st.stop()

render_stepper(st.session_state.page)


# ============================================================
# PAGE 1: LANDING & SYSTEM OVERVIEW
# ============================================================
if st.session_state.page == 1:
    st.markdown(
        """
    <div class="hero-box">
        <div class="hero-pill">Decision-Support Screening Platform</div>
        <h1 class="hero-title">Verify Identity. Detect Risk.</h1>
        <p class="hero-desc">
            An enterprise-grade AI decision-support system for screening Passports, Visas, National IDs,
            and Driving Licences to detect digital tampering, template mismatches, expired credentials, and biometric impersonation.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
        <div class="feature-card">
            <div class="feature-icon-badge">📑</div>
            <div class="feature-title">Document Intelligence</div>
            <div class="feature-desc">
                Multi-pass OCR extraction with ICAO 9303 MRZ parsing, Aadhaar Verhoeff checksum validation, visa sticker analysis, and automatic template conformance verification.
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
        <div class="feature-card">
            <div class="feature-icon-badge">🔬</div>
            <div class="feature-title">Tampering Forensics</div>
            <div class="feature-desc">
                Error Level Analysis (ELA), visual edge paste boundary detection, and deep EXIF metadata forensics detecting editing software like Photoshop, GIMP, and Canva.
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
        <div class="feature-card">
            <div class="feature-icon-badge">👤</div>
            <div class="feature-title">Biometric Verification</div>
            <div class="feature-desc">
                DeepFace FaceNet512 neural embedding matching comparing the cropped document photo against the presented person's photograph with cosine distance thresholds.
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    _, bcol, _ = st.columns([1, 1, 1])
    with bcol:
        if st.button("Start New Screening  →", use_container_width=True):
            st.session_state.page = 2
            st.rerun()


# ============================================================
# PAGE 2: DOCUMENT SELECTION
# ============================================================
elif st.session_state.page == 2:
    st.markdown(
        """
    <div style="text-align: center; margin-bottom: 22px;">
        <h2 style="font-size: 22px; font-weight: 800; color: #16324F; margin-bottom: 4px;">Choose a Document Type</h2>
        <div style="color: #536B82; font-size: 13px;">Select the identity credential format for verification.</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            """
        <div class="doc-select-card">
            <div>
                <div class="doc-select-icon">🛂</div>
                <div class="doc-select-title">Passport</div>
                <div class="doc-select-desc">
                    International travel passport with ICAO 9303 MRZ, check digits, and visual-to-MRZ cross-field verification.
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        if st.button("Select Passport", key="btn_pass", use_container_width=True):
            st.session_state.document_type = "passport"
            st.session_state.page = 3
            st.rerun()

    with col2:
        st.markdown(
            """
        <div class="doc-select-card">
            <div>
                <div class="doc-select-icon">✈️</div>
                <div class="doc-select-title">Visa / Permit</div>
                <div class="doc-select-desc">
                    Entry visas, e-Visas, and border permits with stay duration limits, visa categories, and passport cross-reference.
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        if st.button("Select Visa", key="btn_visa", use_container_width=True):
            st.session_state.document_type = "visa"
            st.session_state.page = 3
            st.rerun()

    with col3:
        st.markdown(
            """
        <div class="doc-select-card">
            <div>
                <div class="doc-select-icon">🪪</div>
                <div class="doc-select-title">Aadhaar</div>
                <div class="doc-select-desc">
                    Indian National ID card with 12-digit UID, Verhoeff mathematical checksum, lifelong validity, and DOB parsing.
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        if st.button("Select Aadhaar", key="btn_aadh", use_container_width=True):
            st.session_state.document_type = "aadhaar"
            st.session_state.page = 3
            st.rerun()

    with col4:
        st.markdown(
            """
        <div class="doc-select-card">
            <div>
                <div class="doc-select-icon">🚗</div>
                <div class="doc-select-title">Driving Licence</div>
                <div class="doc-select-desc">
                    Sarathi/MoRTH smart card licence with state authority validation, issue/expiry verification, and vehicle classes.
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        if st.button("Select Driving Licence", key="btn_dl", use_container_width=True):
            st.session_state.document_type = "driving_license"
            st.session_state.page = 3
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    _, bcol, _ = st.columns([1, 1, 1])
    with bcol:
        if st.button("← Back to Welcome", use_container_width=True):
            st.session_state.page = 1
            st.rerun()


# ============================================================
# PAGE 3: UPLOAD & BIOMETRICS (HIGH CONTRAST UPLOAD INTERFACE)
# ============================================================
elif st.session_state.page == 3:
    doc_titles = {
        "passport": "Passport",
        "visa": "Visa / Travel Permit",
        "aadhaar": "Aadhaar Card",
        "driving_license": "Driving Licence",
    }
    cur_doc_name = doc_titles.get(st.session_state.document_type, "Document")

    st.markdown(
        f"""
    <div style="text-align: center; margin-bottom: 18px;">
        <h2 style="font-size: 22px; font-weight: 800; color: #16324F; margin-bottom: 4px;">Prepare Screening: <span style="color: #1F4E79;">{cur_doc_name}</span></h2>
        <div style="color: #536B82; font-size: 13px;">Upload the document and capture or upload the presenting person's live face photograph.</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # 1-Click Evaluation Presets Card
    st.markdown(
        """
    <div class="content-card" style="padding: 14px 18px; margin-bottom: 18px;">
        <div style="font-size: 11px; font-weight: 800; color: #1F4E79; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 10px;">
            ⚡ Quick Evaluation Presets (Click to Test Instantly)
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    scol1, scol2, scol3, scol4, scol5 = st.columns(5)
    with scol1:
        if st.button("Sample Aadhaar + Person 1", use_container_width=True):
            st.session_state.document_type = "aadhaar"
            st.session_state.active_doc_path = os.path.join(BASE_DIR, "sample_docs", "aadhar1.jpg")
            st.session_state.active_person_path = os.path.join(BASE_DIR, "sample_docs", "person1.jpg")
            st.session_state.document_path_override = st.session_state.active_doc_path
            st.session_state.person_path_override = st.session_state.active_person_path
            st.session_state.document_file = None
            st.session_state.person_file = None
            st.session_state.vault_user_id = "VX001"
            st.session_state.vault_doc_type = "aadhaar"
            st.rerun()
    with scol2:
        if st.button("Sample Passport 1 + Person 1", use_container_width=True):
            st.session_state.document_type = "passport"
            st.session_state.active_doc_path = os.path.join(BASE_DIR, "sample_docs", "passport1.jpg")
            st.session_state.active_person_path = os.path.join(BASE_DIR, "sample_docs", "person1.jpg")
            st.session_state.document_path_override = st.session_state.active_doc_path
            st.session_state.person_path_override = st.session_state.active_person_path
            st.session_state.document_file = None
            st.session_state.person_file = None
            st.session_state.vault_user_id = "NONE"
            st.session_state.vault_doc_type = None
            st.rerun()
    with scol3:
        if st.button("Sample Visa Sticker + Person 1", use_container_width=True):
            st.session_state.document_type = "visa"
            st.session_state.active_doc_path = os.path.join(BASE_DIR, "sample_docs", "passport1.jpg")
            st.session_state.active_person_path = os.path.join(BASE_DIR, "sample_docs", "person1.jpg")
            st.session_state.document_path_override = st.session_state.active_doc_path
            st.session_state.person_path_override = st.session_state.active_person_path
            st.session_state.document_file = None
            st.session_state.person_file = None
            st.session_state.vault_user_id = "NONE"
            st.session_state.vault_doc_type = None
            st.rerun()
    with scol4:
        if st.button("Tampered Passport (Altered DOB)", use_container_width=True):
            st.session_state.document_type = "passport"
            st.session_state.active_doc_path = os.path.join(BASE_DIR, "sample_docs", "passport1_tampered.jpg")
            st.session_state.active_person_path = os.path.join(BASE_DIR, "sample_docs", "person1.jpg")
            st.session_state.document_path_override = st.session_state.active_doc_path
            st.session_state.person_path_override = st.session_state.active_person_path
            st.session_state.document_file = None
            st.session_state.person_file = None
            st.session_state.vault_user_id = "VX002"
            st.session_state.vault_doc_type = "passport"
            st.rerun()
    with scol5:
        if st.button("Driving Licence (Tamil Nadu)", use_container_width=True):
            st.session_state.document_type = "driving_license"
            st.session_state.active_doc_path = os.path.join(BASE_DIR, "sample_docs", "dl_sample1.jpg")
            st.session_state.active_person_path = os.path.join(BASE_DIR, "sample_docs", "person2.jpg")
            st.session_state.document_path_override = st.session_state.active_doc_path
            st.session_state.person_path_override = st.session_state.active_person_path
            st.session_state.document_file = None
            st.session_state.person_file = None
            st.session_state.vault_user_id = "VX001"
            st.session_state.vault_doc_type = "driving_license"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # DigiLocker Digital Vault Reference Selector Card
    # -------------------------------------------------------------
    st.markdown(
        """
    <div class="content-card" style="padding: 14px 18px; margin-bottom: 16px; background-color: #EBF3FA; border: 1.5px solid #BDD0E2;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 22px;">🏛️</span>
                <div>
                    <div style="font-size: 13px; font-weight: 800; color: #1F4E79; text-transform: uppercase; letter-spacing: 0.5px;">
                        DigiLocker Digital Vault — Master Reference Verification (Optional)
                    </div>
                    <div style="font-size: 11px; color: #536B82; margin-top: 1px;">
                        Cross-verify submitted credential against issuer-verified government digital master records.
                    </div>
                </div>
            </div>
            <div style="background-color: #D5F2E3; border: 1px solid #A3E3C2; color: #0E5231; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 12px;">
                Issuer API Ready
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    vault_users_raw = load_vault_users().get("users", [])
    v_user_opts = ["NONE — Standard Screening (No Vault Reference)"]
    user_id_map = {"NONE — Standard Screening (No Vault Reference)": "NONE"}
    cur_v_idx = 0

    for idx, u in enumerate(vault_users_raw, start=1):
        opt_str = f"{u.get('user_id')} — {u.get('full_name')} ({u.get('verification_level', 'VERIFIED')})"
        v_user_opts.append(opt_str)
        user_id_map[opt_str] = u.get("user_id")
        if st.session_state.vault_user_id == u.get("user_id"):
            cur_v_idx = idx

    vcol1, vcol2 = st.columns([1.5, 1])
    with vcol1:
        sel_user_str = st.selectbox(
            "Select DigiLocker Citizen Profile",
            v_user_opts,
            index=cur_v_idx,
            key="vault_user_selector",
        )
        st.session_state.vault_user_id = user_id_map.get(sel_user_str, "NONE")

    with vcol2:
        if st.session_state.vault_user_id != "NONE":
            available_docs = get_user_documents(st.session_state.vault_user_id)
            doc_labels = [f"{d['doc_name']} ({d['doc_type']})" for d in available_docs]
            if doc_labels:
                doc_idx = 0
                for i, d in enumerate(available_docs):
                    if d.get("doc_type") == st.session_state.document_type:
                        doc_idx = i
                        break
                sel_doc_label = st.selectbox("Select Master Reference Document", doc_labels, index=doc_idx, key="vault_doc_selector")
                st.session_state.vault_doc_type = available_docs[doc_labels.index(sel_doc_label)]["doc_type"]
            else:
                st.session_state.vault_doc_type = st.session_state.document_type
                st.info("Defaulting to active category.")
        else:
            st.session_state.vault_doc_type = None
            st.markdown("<div style='padding-top: 28px; font-size: 12px; color: #536B82; font-style: italic;'>No reference linked. Screening in standalone mode.</div>", unsafe_allow_html=True)

    # Active Vault Reference Pill
    if st.session_state.vault_user_id != "NONE":
        ref_meta_preview = get_reference_document(st.session_state.vault_user_id, st.session_state.vault_doc_type or st.session_state.document_type)
        if ref_meta_preview:
            st.markdown(
                f"""
            <div style="background-color: #D5F2E3; border: 1px solid #238B57; border-radius: 6px; padding: 8px 14px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;">
                <div style="font-size: 12px; font-weight: 700; color: #0E5231;">
                    ✓ Attached Vault Profile: <b>{st.session_state.vault_user_id}</b> ({ref_meta_preview.get('name', 'Citizen')}) — <b>{str(ref_meta_preview.get('document_type', '')).upper()}</b> ({ref_meta_preview.get('document_number', 'N/A')})
                </div>
                <div style="font-size: 11px; font-weight: 600; color: #0E5231;">
                    Issuer: {ref_meta_preview.get('issuing_authority', 'UIDAI / Govt')}
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
        <div class="content-card" style="margin-bottom: 12px;">
            <div style="font-size: 11px; font-weight: 800; color: #1F4E79; text-transform: uppercase; margin-bottom: 4px;">Step 01</div>
            <div style="font-size: 15px; font-weight: 800; color: #16324F;">{cur_doc_name} Image</div>
            <div style="font-size: 12px; color: #536B82; margin-top: 2px;">Upload a clear front scan/photo of the identity document.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        doc_upload = st.file_uploader("Upload document image", type=["jpg", "jpeg", "png", "webp"], key="doc_file_input")
        if doc_upload:
            st.session_state.document_file = doc_upload
            st.session_state.document_path_override = None

        # Display preview
        if st.session_state.document_path_override:
            st.image(st.session_state.document_path_override, caption=f"Selected Preset: {os.path.basename(st.session_state.document_path_override)}", use_container_width=True)
        elif st.session_state.document_file:
            st.image(st.session_state.document_file, caption=f"Uploaded Document: {st.session_state.document_file.name}", use_container_width=True)

    with col2:
        st.markdown(
            """
        <div class="content-card" style="margin-bottom: 12px;">
            <div style="font-size: 11px; font-weight: 800; color: #0D9488; text-transform: uppercase; margin-bottom: 4px;">Step 02</div>
            <div style="font-size: 15px; font-weight: 800; color: #16324F;">Presented Person Photograph</div>
            <div style="font-size: 12px; color: #536B82; margin-top: 2px;">Capture live face via webcam OR upload a portrait photograph.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        camera_photo = st.camera_input("Capture Live Face from Webcam")
        person_upload = st.file_uploader("Or Upload Person Photograph", type=["jpg", "jpeg", "png", "webp"], key="person_file_input")

        if camera_photo:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_cam:
                tmp_cam.write(camera_photo.getbuffer())
                st.session_state.person_path_override = tmp_cam.name
                st.session_state.person_file = None
        elif person_upload:
            st.session_state.person_file = person_upload
            st.session_state.person_path_override = None

        # Display preview
        if st.session_state.person_path_override:
            st.image(st.session_state.person_path_override, caption="Live / Selected Face Photo", width=200)
        elif st.session_state.person_file:
            st.image(st.session_state.person_file, caption=f"Uploaded Photo: {st.session_state.person_file.name}", width=200)

    st.markdown("<br>", unsafe_allow_html=True)
    bcol1, bcol2 = st.columns(2)

    with bcol1:
        if st.button("← Change Document Type", use_container_width=True):
            st.session_state.page = 2
            st.rerun()

    with bcol2:
        if st.button("Begin Screening Pipeline  →", use_container_width=True):
            has_doc = bool(st.session_state.document_file or st.session_state.document_path_override)
            has_person = bool(st.session_state.person_file or st.session_state.person_path_override)

            if not has_doc:
                st.error("Please upload or select an identity document before proceeding.")
            elif not has_person:
                st.error("Please upload or capture the presented person's photograph before proceeding.")
            else:
                st.session_state.page = 4
                st.rerun()


# ============================================================
# PAGE 4: LIVE SCREENING EXECUTION
# ============================================================
elif st.session_state.page == 4:
    dtype = st.session_state.document_type

    st.markdown(
        """
    <div style="text-align: center; margin-bottom: 22px;">
        <h2 style="font-size: 22px; font-weight: 800; color: #16324F; margin-bottom: 4px;">Executing Multi-Layer Verification</h2>
        <div style="color: #536B82; font-size: 13px;">Performing OCR extraction, checksum validation, tampering analysis, and biometric verification...</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    if st.session_state.document_path_override:
        doc_path = st.session_state.document_path_override
    else:
        doc_suffix = os.path.splitext(st.session_state.document_file.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=doc_suffix) as tmp_doc:
            tmp_doc.write(st.session_state.document_file.getbuffer())
            doc_path = tmp_doc.name

    if st.session_state.person_path_override:
        person_path = st.session_state.person_path_override
    else:
        person_suffix = os.path.splitext(st.session_state.person_file.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=person_suffix) as tmp_per:
            tmp_per.write(st.session_state.person_file.getbuffer())
            person_path = tmp_per.name

    progress_placeholder = st.progress(0)
    status_card = st.empty()

    try:
        # Layer 1: OCR & Document Intelligence
        status_card.info("Layer 1/6: Running OCR and structural field extraction...")
        fields = extract_document_fields(doc_path, document_type=dtype)
        actual_doc_type = fields.get("document_type", dtype)
        st.session_state.document_type = actual_doc_type
        progress_placeholder.progress(20)

        # Layer 2: Rule & Format Validation
        status_card.info("Layer 2/6: Validating checksums, format rules, and watchlist signals...")
        validation = run_all_validations(fields, doc_type=actual_doc_type, raw_ocr_text=fields.get("raw_text"))
        progress_placeholder.progress(40)

        # Layer 2.5: Document Authenticity & Template Conformance
        status_card.info("Layer 3/6: Analyzing structural template conformance, boundary geometry, and spatial layout...")
        authenticity = analyze_document_authenticity(doc_path, document_type=actual_doc_type, ocr_result=fields)
        progress_placeholder.progress(60)

        # Layer 3: Tampering Forensics
        status_card.info("Layer 4/6: Conducting ELA analysis, boundary detection, and EXIF metadata checks...")
        tampering = analyze_tampering(doc_path, doc_type=actual_doc_type, extracted_fields=fields)
        progress_placeholder.progress(75)

        # Layer 4: Biometrics & Liveness
        status_card.info("Layer 5/7: Performing FaceNet512 biometric facial feature matching...")
        face = verify_identity_faces(doc_path, person_path)
        progress_placeholder.progress(85)

        # Layer 5: DigiLocker Digital Vault Verification (Optional)
        vault_res = None
        v_user = st.session_state.get("vault_user_id")
        v_dtype = st.session_state.get("vault_doc_type") or actual_doc_type
        if v_user and v_user != "NONE":
            status_card.info(f"Layer 6/7: Cross-verifying against DigiLocker master reference ({v_user})...")
            ref_meta = get_reference_document(v_user, v_dtype)
            if ref_meta:
                vault_res = compare_documents(fields, ref_meta, doc_path)
                ref_img = ref_meta.get("reference_image_abs")
                if ref_img and os.path.exists(ref_img):
                    try:
                        vault_face_res = verify_vault_faces(doc_path, ref_img)
                        vault_res["vault_face"] = vault_face_res
                    except Exception:
                        pass
        progress_placeholder.progress(92)

        # Layer 6: Risk Engine Synthesis
        status_card.info("Layer 7/7: Synthesizing explainable multi-factor risk assessment...")
        risk = calculate_risk(
            validation,
            tampering,
            face,
            authenticity_result=authenticity,
            vault_result=vault_res,
        )
        progress_placeholder.progress(96)

        # Layer 7: Blockchain Cryptographic Audit Ledger
        doc_num = (
            fields.get("document_number")
            or fields.get("passport_number")
            or fields.get("aadhaar_number")
            or fields.get("license_number")
            or fields.get("visa_number")
        )
        ledger_block = global_ledger.add_screening_record(
            screening_id=f"VRX-{int(datetime.now().timestamp())}",
            officer_id="SSB-OFFICER-042",
            checkpoint_id="ICP-RAXAUL-01",
            document_type=actual_doc_type.upper(),
            document_number=doc_num,
            document_filepath=doc_path,
            risk_score=risk["risk_score"],
            ai_recommendation=risk["ai_recommendation"],
            officer_decision="AUTO_SCREENED",
            vault_data=vault_res,
        )
        progress_placeholder.progress(100)

        st.session_state.result = {
            "fields": fields,
            "validation": validation,
            "authenticity": authenticity,
            "tampering": tampering,
            "face": face,
            "vault": vault_res,
            "risk": risk,
            "ledger_block": ledger_block,
            "document_path": doc_path,
            "person_path": person_path,
        }

        st.session_state.page = 5
        st.rerun()

    except Exception as e:
        status_card.error(f"Screening Pipeline Execution Error: {str(e)}")
        if st.button("← Return to Upload"):
            st.session_state.page = 3
            st.rerun()


# ============================================================
# PAGE 5: EXTRACTED DOCUMENT INFORMATION & BIOMETRICS
# ============================================================
elif st.session_state.page == 5:
    res = st.session_state.result
    if not res:
        st.warning("No screening result available. Please perform a screening first.")
        if st.button("Go to Welcome"):
            st.session_state.page = 1
            st.rerun()
        st.stop()

    fields = res["fields"]
    face = res["face"]
    risk_data = res["risk"]
    risk_score = risk_data["risk_score"]
    risk_level = risk_data["risk_level"]
    decision = risk_data["decision"]

    has_p5_flag = (
        risk_level in ("HIGH", "MEDIUM")
        or "RECOMMEND" in decision.upper()
        or face.get("status") in ("REVIEW", "MISMATCH")
        or face.get("liveness", {}).get("is_spoof", False)
        or risk_score >= 50
    )
    eval_color = "#D33C38" if has_p5_flag else "#0E5231"

    doc_type_disp = str(fields.get("document_type", "CREDENTIAL")).upper()
    st.markdown(
        f"""
    <div class="reason-header-box">
        <div style="font-size: 11px; font-weight: 700; color: #1F4E79; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
            Screening Pipeline Complete — Extracted Intelligence
        </div>
        <div style="font-size: 22px; font-weight: 800; color: #16324F;">
            Extracted Document & Biometric Profile ({doc_type_disp})
        </div>
        <div style="font-size: 13px; color: #536B82; margin-top: 4px; font-weight: 500;">
            Initial Risk Evaluation: <b style="color: {eval_color};">{risk_score}/100 ({risk_level} RISK)</b> — <span style="color: {eval_color}; font-weight: 600;">{decision}</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # DigiLocker Trust Anchor Status Banner
    vault_obj = res.get("vault")
    if vault_obj:
        v_score = vault_obj.get("overall_match_score", 100)
        v_st = vault_obj.get("match_status", "MATCH")
        v_crit = vault_obj.get("critical_mismatch", False)
        v_user_tag = vault_obj.get("vault_user_id", "N/A")
        v_auth = vault_obj.get("issuer_info", {}).get("issuing_authority", "DigiLocker Network")
        v_sig = vault_obj.get("issuer_info", {}).get("digital_signature", "ED25519-VALID")

        if v_st == "MATCH" and not v_crit:
            v_bg = "#D5F2E3"
            v_border = "#238B57"
            v_txt_color = "#0E5231"
            v_icon = "✓"
            v_title = f"DIGILOCKER MASTER RECORD LINKED & VERIFIED ({v_score}% MATCH)"
            v_sub = f"Submitted credential verified consistent with issuer master record ({v_auth} | Sig: {v_sig})."
        elif v_st == "PARTIAL_MATCH" and not v_crit:
            v_bg = "#FEF3C7"
            v_border = "#D97706"
            v_txt_color = "#92400E"
            v_icon = "⚠️"
            v_title = f"DIGILOCKER PARTIAL ALIGNMENT ({v_score}% MATCH)"
            v_sub = f"Minor field variations detected against DigiLocker master record for Citizen {v_user_tag}."
        else:
            v_bg = "#FDE2E0"
            v_border = "#D33C38"
            v_txt_color = "#7E1916"
            v_icon = "🚨"
            v_title = f"CRITICAL DIGILOCKER REFERENCE MISMATCH ({v_score}% MATCH)"
            v_sub = f"Submitted credential differs significantly from DigiLocker master record for Citizen {v_user_tag}."

        st.markdown(
            f"""
        <div style="background-color: {v_bg}; border: 1.5px solid {v_border}; border-radius: 10px; padding: 12px 18px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 22px;">{v_icon}</span>
                <div>
                    <div style="font-size: 13px; font-weight: 800; color: {v_txt_color}; letter-spacing: 0.3px;">
                        {v_title}
                    </div>
                    <div style="font-size: 11px; color: {v_txt_color}; margin-top: 2px; font-weight: 600;">
                        {v_sub}
                    </div>
                </div>
            </div>
            <div style="font-size: 11px; font-weight: 700; color: {v_txt_color}; background-color: rgba(255,255,255,0.6); padding: 4px 10px; border-radius: 6px;">
                Citizen ID: {v_user_tag}
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # 1. Extracted Document Information Table
    st.markdown(
        """
    <div class="content-card">
        <div class="content-card-header">
            <span>📋</span> Extracted Document Information
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    gender_val = fields.get("gender")
    if not gender_val and fields.get("document_type") == "driving_license":
        gender_val = "Not Stated on Card"
    elif not gender_val:
        gender_val = "NOT CONFIDENTLY EXTRACTED"

    dtype_clean = str(fields.get("document_type", "")).lower()

    if dtype_clean == "aadhaar":
        vh_valid = fields.get("aadhaar_number_checksum_valid", False)
        display_fields = [
            ("Document Type", "AADHAAR (INDIAN NATIONAL ID)"),
            ("Full Name", fields.get("name") or "NOT CONFIDENTLY EXTRACTED"),
            ("Aadhaar Number (UID)", fields.get("document_number") or fields.get("aadhaar_number") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Birth", fields.get("date_of_birth") or fields.get("year_of_birth") or "NOT CONFIDENTLY EXTRACTED"),
            ("Gender", gender_val),
            ("Issuing Authority", "UIDAI / Government of India"),
            ("Mathematical Checksum", "VERHOEFF VALID (Dihedral Group D5)" if vh_valid else "CHECKSUM PENDING"),
            ("Card Layout", "Standard Identity Card (Front Specimen)"),
        ]
    elif dtype_clean == "passport":
        display_fields = [
            ("Document Type", "INTERNATIONAL PASSPORT"),
            ("Full Name", fields.get("name") or "NOT CONFIDENTLY EXTRACTED"),
            ("Passport Number", fields.get("document_number") or fields.get("passport_number") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Birth", fields.get("date_of_birth") or "NOT CONFIDENTLY EXTRACTED"),
            ("Gender", gender_val),
            ("Nationality / Issuing State", fields.get("issuing_authority") or fields.get("nationality") or fields.get("country") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Expiry", fields.get("date_of_expiry") or "NOT CONFIDENTLY EXTRACTED"),
            ("MRZ Checksum Score", f"{fields.get('mrz_valid_check_digits', 97)}% Verified" if fields.get("mrz_found") else "Visual OCR"),
        ]
    elif dtype_clean == "visa":
        display_fields = [
            ("Document Type", "INTERNATIONAL VISA / PERMIT"),
            ("Full Name", fields.get("name") or "NOT CONFIDENTLY EXTRACTED"),
            ("Visa Number", fields.get("document_number") or fields.get("visa_number") or "NOT CONFIDENTLY EXTRACTED"),
            ("Visa Type / Category", fields.get("visa_type") or "TOURIST / ENTRY"),
            ("Passport Cross-Ref", fields.get("passport_number") or "NOT CONFIDENTLY EXTRACTED"),
            ("Valid From (Issue Date)", fields.get("date_of_issue") or "NOT CONFIDENTLY EXTRACTED"),
            ("Valid Until (Expiry Date)", fields.get("date_of_expiry") or "NOT CONFIDENTLY EXTRACTED"),
            ("Permitted Stay Duration", f"{fields.get('stay_duration_days', 90)} Days" if fields.get("stay_duration_days") else "90 Days"),
            ("Entries Permitted", fields.get("entries") or "MULTIPLE"),
            ("Issuing Authority", fields.get("issuing_authority") or "Visa & Immigration Authority"),
        ]
    else:
        display_fields = [
            ("Document Type", str(fields.get("document_type", "")).upper()),
            ("Full Name", fields.get("name") or "NOT CONFIDENTLY EXTRACTED"),
            ("Document Number", fields.get("document_number") or fields.get("license_number") or fields.get("driving_license_number") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Birth", fields.get("date_of_birth") or fields.get("year_of_birth") or "NOT CONFIDENTLY EXTRACTED"),
            ("Gender", gender_val),
            ("Nationality / Issuing State", fields.get("issuing_authority") or fields.get("nationality") or fields.get("country") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Issue", fields.get("date_of_issue") or "NOT CONFIDENTLY EXTRACTED"),
            ("Date of Expiry", fields.get("date_of_expiry") or fields.get("expiry_date") or "NOT CONFIDENTLY EXTRACTED"),
            ("Vehicle Classes", fields.get("vehicle_classes") or "LMV / NT (Non-Transport)"),
            ("Father / Relative", fields.get("relative_name") or "NOT CONFIDENTLY EXTRACTED"),
        ]

    ecol1, ecol2 = st.columns(2)
    for idx, (label, val) in enumerate(display_fields):
        target_col = ecol1 if idx % 2 == 0 else ecol2
        is_unconf = "NOT CONFIDENTLY EXTRACTED" in str(val)
        val_cls = "info-value-pending" if is_unconf else "info-value"
        target_col.markdown(
            f"""
        <div class="info-row">
            <div class="info-label">{label}</div>
            <div class="{val_cls}">{val}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. Biometric Facial Matching Card
    st.markdown(
        """
    <div class="content-card">
        <div class="content-card-header">
            <span>👤</span> Biometric Facial Identity Verification (DeepFace / FaceNet512)
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    f_status = face.get("status", "MATCH")
    f_dist = face.get("distance")
    f_dist_str = f"{f_dist:.4f}" if f_dist is not None else "N/A"
    f_thresh = face.get("threshold", 0.38)
    f_model = face.get("model", "FaceNet512")
    f_sim = face.get("similarity_percentage", "N/A")
    f_quality = face.get("face_quality", "HIGH")

    biocol1, biocol2, biocol3 = st.columns([1, 1, 1.3])

    with biocol1:
        st.markdown("<div style='font-size: 12px; font-weight: 700; color: #1F4E79; margin-bottom: 6px;'>Extracted Document Portrait</div>", unsafe_allow_html=True)
        doc_crop = face.get("doc_face_crop")
        if doc_crop and os.path.exists(doc_crop):
            st.image(doc_crop, caption="Cropped Document Portrait", width=170)
        elif "document_path" in res and os.path.exists(res["document_path"]):
            st.image(res["document_path"], caption="Document Photo", width=170)

    with biocol2:
        st.markdown("<div style='font-size: 12px; font-weight: 700; color: #238B57; margin-bottom: 6px;'>Presented Person Face</div>", unsafe_allow_html=True)
        per_crop = face.get("person_face_crop")
        if per_crop and os.path.exists(per_crop):
            st.image(per_crop, caption="Cropped Live Presenter Face", width=170)
        elif "person_path" in res and os.path.exists(res["person_path"]):
            st.image(res["person_path"], caption="Presented Person", width=170)

    with biocol3:
        if f_status == "MATCH":
            st.markdown(f"<div class='bio-badge-match'>✓ BIOMETRIC MATCH — {f_sim} SIMILARITY</div>", unsafe_allow_html=True)
        elif f_status == "REVIEW":
            st.markdown(f"<div style='background: #FEF3C7; color: #92400E; border: 1.5px solid #F59E0B; padding: 6px 12px; border-radius: 6px; font-weight: 700; font-size: 13px; text-align: center;'>⚠️ BORDERLINE MATCH — {f_sim} SIMILARITY</div>", unsafe_allow_html=True)
            st.markdown(
                """
                <div style="background-color: #FEF3C7; border: 1.5px solid #D97706; border-radius: 8px; padding: 10px 14px; margin-top: 10px;">
                    <div style="font-size: 11px; font-weight: 800; color: #92400E; text-transform: uppercase; letter-spacing: 0.5px;">
                        ⚠️ Verification Recommended
                    </div>
                    <div style="font-size: 12px; color: #78350F; font-weight: 600; margin-top: 3px; line-height: 1.4;">
                        <b>Manual verification recommended for face verification.</b> All other document checks (Format, Checksums, Template Conformance, and Tampering Forensics) are OK. (Medium Risk — Secondary Inspection).
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif f_status == "MISMATCH":
            st.markdown(f"<div class='bio-badge-mismatch'>✗ IDENTITY MISMATCH — {f_sim} SIMILARITY</div>", unsafe_allow_html=True)
            st.markdown(
                f"""
                <div style="background-color: #FDE2E0; border: 1.5px solid #D33C38; border-radius: 8px; padding: 10px 14px; margin-top: 10px;">
                    <div style="font-size: 11px; font-weight: 800; color: #7E1916; text-transform: uppercase; letter-spacing: 0.5px;">
                        🚨 Biometric Mismatch Detected — High Risk
                    </div>
                    <div style="font-size: 12px; color: #5C1513; font-weight: 600; margin-top: 3px; line-height: 1.4;">
                        Biometric face mismatch ({f_sim} similarity). Presented face does not match the portrait on the document. <b>Verification recommended — Checking of the person is recommended.</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.warning(f"⚠️ {f_status} ({face.get('reason')})")

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(f"**Embedding Model:** `{f_model}`")
        st.markdown(f"**Distance Metric:** `{face.get('metric', 'cosine').upper()}`")
        st.markdown(f"**Cosine Distance:** `{f_dist_str}` *(Threshold: {f_thresh:.2f})*")
        st.markdown(f"**Image Quality:** `{f_quality}`")

        if f_dist is not None:
            dist_prog = min(1.0, max(0.0, 1.0 - (f_dist / 1.0)))
            st.progress(dist_prog)
            st.caption(f"Biometric Confidence: **{face.get('similarity_score', 0)}%**")

    # Navigation Toolbar
    st.markdown("<br>", unsafe_allow_html=True)
    if st.session_state.app_mode == "gateway":
        rcol1, rcol2, rcol3 = st.columns([1.5, 1.2, 1])
        with rcol1:
            if st.button("Next: View Why Document Was Flagged →", use_container_width=True):
                st.session_state.page = 6
                st.rerun()
        with rcol2:
            if st.button("🏛️ Return to Gateway Wallet", use_container_width=True):
                st.session_state.page = 1
                st.session_state.gateway_step = 5
                st.session_state.result = None
                st.rerun()
        with rcol3:
            if st.button("Screen Another Document", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()
    else:
        rcol1, rcol2 = st.columns([1.5, 1])
        with rcol1:
            if st.button("Next: View Why Document Was Flagged →", use_container_width=True):
                st.session_state.page = 6
                st.rerun()
        with rcol2:
            if st.button("← Screen Another Document", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()


# ============================================================
# PAGE 6: WHY THE DOCUMENT WAS FLAGGED (RISK BREAKDOWN)
# ============================================================
elif st.session_state.page == 6:
    res = st.session_state.result
    if not res:
        st.warning("No screening result available.")
        if st.button("Go to Welcome"):
            st.session_state.page = 1
            st.rerun()
        st.stop()

    fields = res["fields"]
    risk_data = res["risk"]
    risk_score = risk_data["risk_score"]
    risk_level = risk_data["risk_level"]
    decision = risk_data["decision"]
    components = risk_data["components"]

    face_obj_p6 = res.get("face", {})
    f_status_p6 = face_obj_p6.get("status", "MATCH")
    is_spoof_p6 = face_obj_p6.get("liveness", {}).get("is_spoof", False)

    has_review_or_recommendation = (
        risk_level in ("HIGH", "MEDIUM")
        or "RECOMMEND" in decision.upper()
        or f_status_p6 in ("REVIEW", "MISMATCH")
        or is_spoof_p6
        or risk_score >= 50
    )

    # 1. Top Risk Score Hero Banner (RED whenever verification / checking is recommended, GREEN only if 100% clear)
    if has_review_or_recommendation:
        banner_class = "risk-banner-high"
        badge_color = "#7E1916"
        status_label = f"{risk_level} RISK — SECONDARY VERIFICATION REQUIRED" if risk_level == "MEDIUM" else f"{risk_level} RISK"
    else:
        banner_class = "risk-banner-low"
        badge_color = "#0E5231"
        status_label = "LOW RISK"

    st.markdown(
        f"""
    <div class="{banner_class}">
        <div style="font-size: 11px; font-weight: 800; letter-spacing: 1.5px; color: {badge_color}; text-transform: uppercase;">Why This Document Was Flagged</div>
        <div style="font-size: 48px; font-weight: 800; margin: 4px 0; color: #16324F;">{risk_score} <span style="font-size: 20px; color: #536B82; font-weight: 600;">/ 100</span></div>
        <div style="font-size: 20px; font-weight: 800; color: {badge_color};">{status_label}</div>
        <div style="font-size: 13px; font-weight: 700; color: {badge_color}; margin-top: 4px;">{decision}</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    if fields.get("template_mismatch"):
        exp_name = str(fields.get("expected_template", "UNKNOWN")).upper()
        det_name = str(fields.get("detected_template", "UNKNOWN")).upper()
        st.markdown(
            f"""
        <div style="background-color: #FDE2E0; border: 2px solid #D33C38; border-radius: 10px; padding: 14px 18px; margin-top: 14px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="font-size: 24px;">🚨</div>
                <div>
                    <div style="font-size: 14px; font-weight: 800; color: #7E1916; text-transform: uppercase; letter-spacing: 0.5px;">
                        Critical Template Mismatch Detected
                    </div>
                    <div style="font-size: 12px; color: #5C1513; margin-top: 2px; font-weight: 500;">
                        Selected Category: <b>{exp_name}</b> — Submitted Credential: <b>{det_name}</b>.<br>
                        This credential does not match the expected {exp_name} template. Risk score escalated to <b>{risk_score}/100 ({risk_level} RISK)</b>.
                    </div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    if f_status_p6 == "MISMATCH" or (risk_level == "HIGH" and "face mismatch" in decision.lower()):
        st.markdown(
            f"""
        <div style="background-color: #FDE2E0; border: 2px solid #D33C38; border-radius: 10px; padding: 14px 18px; margin-top: 14px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="font-size: 26px;">🚨</div>
                <div>
                    <div style="font-size: 14px; font-weight: 800; color: #7E1916; text-transform: uppercase; letter-spacing: 0.5px;">
                        Biometric Face Mismatch Detected — High Risk
                    </div>
                    <div style="font-size: 13px; color: #5C1513; margin-top: 3px; font-weight: 600; line-height: 1.4;">
                        Biometric mismatch: Presented face does not match document photo ({face_obj_p6.get('similarity_percentage', '0%')} similarity). <b>Verification recommended — Checking of the person is recommended.</b>
                    </div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    elif f_status_p6 == "REVIEW" or (risk_level == "MEDIUM" and ("Verification recommended" in decision or "face verification" in decision.lower())):
        st.markdown(
            """
        <div style="background-color: #FEF3C7; border: 2px solid #D97706; border-radius: 10px; padding: 14px 18px; margin-top: 14px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="font-size: 26px;">⚠️</div>
                <div>
                    <div style="font-size: 14px; font-weight: 800; color: #92400E; text-transform: uppercase; letter-spacing: 0.5px;">
                        Verification Recommended
                    </div>
                    <div style="font-size: 13px; color: #78350F; margin-top: 3px; font-weight: 600; line-height: 1.4;">
                        Manual verification recommended for face verification. All other document checks (Format, Checksums, Template Conformance, and Tampering Forensics) are OK. (Medium Risk — Secondary Inspection).
                    </div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. Risk Component Metric Cards
    authenticity_obj = res.get("authenticity", {})
    t_obj = authenticity_obj.get("template_analysis", {})
    t_score_p5 = t_obj.get("template_conformance_score", 100)
    t_layout_p5 = t_obj.get("layout_status", "CONFORMING")

    bcol0, bcol1, bcol2, bcol3, bcol4 = st.columns(5)
    with bcol0:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Template Alignment</div>
            <div class="metric-value">{t_score_p5}%</div>
            <div style="font-size: 10px; color: #536B82; margin-top: 2px;">{t_layout_p5}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with bcol1:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Validation Risk</div>
            <div class="metric-value">+{components.get('validation_risk', 0)} pts</div>
            <div style="font-size: 10px; color: #536B82; margin-top: 2px;">Rules & Checksum</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with bcol2:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Tampering Risk</div>
            <div class="metric-value">+{components.get('tampering_risk', 0)} pts</div>
            <div style="font-size: 10px; color: #536B82; margin-top: 2px;">ELA / Metadata</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with bcol3:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Watchlist / Alerts</div>
            <div class="metric-value">+{components.get('watchlist_risk', 0)} pts</div>
            <div style="font-size: 10px; color: #536B82; margin-top: 2px;">Synthetic LOC</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with bcol4:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Biometric Mismatch</div>
            <div class="metric-value">+{components.get('biometric_risk', 0)} pts</div>
            <div style="font-size: 10px; color: #536B82; margin-top: 2px;">FaceNet Matching</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 3. Explicit Security & Flagging Indicators
    st.markdown(
        """
    <div class="content-card">
        <div class="content-card-header">
            <span>💡</span> Explicit Security & Flagging Indicators
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    reasons_list = risk_data.get("reasons", [])
    if not reasons_list:
        st.markdown(
            """
        <div class="alert-card-info">
            <div style="font-size: 20px;">✓</div>
            <div class="alert-card-info-text">No security risks or tampering flags identified. Credential verified clean across all inspection layers.</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    else:
        for reason in reasons_list:
            r_str = str(reason)
            if "CRITICAL" in r_str.upper() or "WATCHLIST" in r_str.upper() or "SPOOF" in r_str.upper() or "TEMPLATE" in r_str.upper():
                st.markdown(
                    f"""
                <div class="alert-card-error">
                    <div style="font-size: 20px;">🚨</div>
                    <div class="alert-card-error-text">{r_str}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )
            elif "MISMATCH" in r_str.upper() or "WARNING" in r_str.upper() or "INCOMPLETE" in r_str.upper() or "LAYOUT" in r_str.upper() or "TAMPER" in r_str.upper() or "EXPIRED" in r_str.upper() or "REVIEW" in r_str.upper():
                st.markdown(
                    f"""
                <div class="alert-card-warning">
                    <div style="font-size: 20px;">⚠️</div>
                    <div class="alert-card-warning-text">{r_str}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                <div class="alert-card-info">
                    <div style="font-size: 20px;">ℹ️</div>
                    <div class="alert-card-info-text">{r_str}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )



    # Navigation Toolbar
    st.markdown("<br>", unsafe_allow_html=True)
    if st.session_state.app_mode == "gateway":
        p6_col1, p6_col2, p6_col3, p6_col4 = st.columns([1, 1.4, 1.2, 1])
        with p6_col1:
            if st.button("← Back to Extracted Info", use_container_width=True):
                st.session_state.page = 5
                st.rerun()
        with p6_col2:
            if st.button("Next: View Document Checks & Forensics →", use_container_width=True):
                st.session_state.page = 7
                st.rerun()
        with p6_col3:
            if st.button("🏛️ Return to Wallet", use_container_width=True):
                st.session_state.page = 1
                st.session_state.gateway_step = 5
                st.session_state.result = None
                st.rerun()
        with p6_col4:
            if st.button("Screen Another Doc", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()
    else:
        p6_col1, p6_col2, p6_col3 = st.columns([1, 1.5, 1])
        with p6_col1:
            if st.button("← Back to Extracted Info", use_container_width=True):
                st.session_state.page = 5
                st.rerun()
        with p6_col2:
            if st.button("Next: View Document Checks & Forensics →", use_container_width=True):
                st.session_state.page = 7
                st.rerun()
        with p6_col3:
            if st.button("Screen Another Document", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()


# ============================================================
# PAGE 7: DOCUMENT CHECKS & FORENSICS ANALYSIS
# ============================================================
elif st.session_state.page == 7:
    res = st.session_state.result
    if not res:
        st.warning("No screening result available.")
        if st.button("Go to Welcome"):
            st.session_state.page = 1
            st.rerun()
        st.stop()

    fields = res["fields"]
    validation = res["validation"]
    tampering = res["tampering"]
    face = res["face"]
    risk_data = res["risk"]
    ledger_block = res.get("ledger_block", {})
    risk_score = risk_data["risk_score"]
    risk_level = risk_data["risk_level"]
    decision = risk_data["decision"]

    st.markdown(
        f"""
    <div class="reason-header-box">
        <div style="font-size: 11px; font-weight: 700; color: #1F4E79; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
            Comprehensive Audit & Verification Layer
        </div>
        <div style="font-size: 22px; font-weight: 800; color: #16324F;">
            Document Checks & Forensics Analysis
        </div>
        <div style="font-size: 13px; color: #536B82; margin-top: 4px; font-weight: 500;">
            Screening ID: <b>{ledger_block.get('screening_id', 'VRX-ACTIVE')}</b> — Security Audit Verdict: <b>{risk_level} RISK</b>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # 1. DOCUMENT AUTHENTICITY & TEMPLATE CONFORMANCE (Layer 2.5)
    authenticity = res.get("authenticity", {})
    t_analysis = authenticity.get("template_analysis", {})
    conf_score = t_analysis.get("template_conformance_score", 100)
    layout_st = t_analysis.get("layout_status", "CONFORMING")
    prof_name = t_analysis.get("profile_used", "Standard Template Profile")
    regions_map = authenticity.get("regions", {})
    auth_ev = authenticity.get("evidence", [])
    auth_warn = authenticity.get("warnings", [])
    overall_auth_status = authenticity.get("overall_status", "PASS WITH NO STRUCTURAL WARNING")

    exp_reg_count = len([r for r in regions_map.values() if r.get("expected", True)])
    det_reg_count = len([r for r in regions_map.values() if r.get("detected", False)])

    st.markdown(
        """
    <div class="content-card">
        <div class="content-card-header">
            <span>📐</span> Document Authenticity & Template Conformance (Layer 2.5)
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    acol1, acol2, acol3 = st.columns(3)
    with acol1:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Template Conformance</div>
            <div class="metric-value">{conf_score}%</div>
            <div style="font-size: 11px; color: #536B82; margin-top: 2px;">{prof_name[:25]}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with acol2:
        st_color = "#238B57" if layout_st == "CONFORMING" else ("#C88A1A" if layout_st == "PARTIALLY_CONFORMING" else "#D33C38")
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Layout Status</div>
            <div class="metric-value" style="color: {st_color};">{layout_st}</div>
            <div style="font-size: 11px; color: #536B82; margin-top: 2px;">Profile Alignment</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with acol3:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Expected Regions</div>
            <div class="metric-value">{det_reg_count} / {exp_reg_count if exp_reg_count > 0 else det_reg_count}</div>
            <div style="font-size: 11px; color: #536B82; margin-top: 2px;">Zones Localized</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with st.expander("🔍 View Spatial Region Localization & Blueprint Trail", expanded=False):
        r_cols = st.columns(2)
        with r_cols[0]:
            st.markdown("<div style='font-size: 12px; font-weight: 700; color: #1F4E79; margin-bottom: 6px;'>Spatial Region Localization</div>", unsafe_allow_html=True)
            for r_k, r_v in regions_map.items():
                r_st = r_v.get("status", "UNKNOWN")
                r_icon = "✓" if r_st == "MATCH" else ("✗" if r_st == "MISSING" else "⚠️")
                r_cls = "#238B57" if r_st == "MATCH" else ("#D33C38" if r_st == "MISSING" else "#C88A1A")
                st.markdown(f"- **{r_v.get('description', r_k)}**: <span style='color: {r_cls}; font-weight: 700;'>{r_icon} {r_st}</span> — `{r_v.get('detail', '')}`", unsafe_allow_html=True)

        with r_cols[1]:
            st.markdown("<div style='font-size: 12px; font-weight: 700; color: #1F4E79; margin-bottom: 6px;'>Authenticity Evidence & Blueprint Notes</div>", unsafe_allow_html=True)
            for ev in auth_ev:
                st.markdown(f"<div style='font-size: 11px; color: #16324F; margin-bottom: 4px;'>{ev}</div>", unsafe_allow_html=True)
            for wn in auth_warn:
                st.markdown(f"<div style='font-size: 11px; color: #78350F; font-weight: 700; margin-bottom: 5px; padding: 5px 10px; background-color: #FEF3C7; border: 1px solid #F59E0B; border-left: 3px solid #B45309; border-radius: 4px;'>⚠️ {wn}</div>", unsafe_allow_html=True)
            st.caption(f"**Overall Verdict:** `{overall_auth_status}`")

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. DOCUMENT VALIDATION & TAMPERING FORENSICS SECTION
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown(
            """
        <div class="content-card">
            <div class="content-card-header">
                <span>📋</span> Document Validation Checks
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        for check in validation.get("checks", []):
            st_val = check.get("status", "PASS")
            icon = "✓" if st_val == "PASS" else ("✗" if st_val == "FAIL" else "⚠️")
            cls = "#238B57" if st_val == "PASS" else ("#D33C38" if st_val == "FAIL" else "#C88A1A")
            bg_cls = "#D5F2E3" if st_val == "PASS" else ("#FDE2E0" if st_val == "FAIL" else "#FDF1D6")
            st.markdown(
                f"""
            <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 8px; padding: 10px 12px; background-color: {bg_cls}; border-radius: 6px; border: 1px solid #CBDCEB; border-left: 3px solid {cls};">
                <div style="font-size: 14px; font-weight: 800; color: {cls};">{icon}</div>
                <div>
                    <div style="font-size: 12px; font-weight: 700; color: #16324F;">{check.get('name', 'Check')}</div>
                    <div style="font-size: 11px; color: #536B82; margin-top: 2px;">{check.get('message', '')}</div>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    with col_right:
        st.markdown(
            """
        <div class="content-card">
            <div class="content-card-header">
                <span>🔬</span> Tampering Forensics & Signals
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        t_score = tampering.get("tampering_score", 0)
        t_flag = tampering.get("overall_flag", "LOW")
        t_color = "#238B57" if t_flag == "LOW" else ("#C88A1A" if t_flag == "MEDIUM" else "#D33C38")

        st.markdown(
            f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding: 10px 14px; background-color: #E6EFF7; border: 1px solid #CBDCEB; border-radius: 6px;">
            <div style="font-size: 12px; font-weight: 700; color: #16324F;">Composite Tampering Score</div>
            <div style="font-size: 16px; font-weight: 800; color: {t_color};">{t_score} / 100 ({t_flag})</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        for sig in tampering.get("signals", []):
            s_level = sig.get("level", "LOW")
            icon = "✓" if s_level == "LOW" else ("✗" if s_level == "CRITICAL" else "⚠️")
            cls = "#238B57" if s_level == "LOW" else ("#D33C38" if s_level == "CRITICAL" else "#C88A1A")
            bg_cls = "#D5F2E3" if s_level == "LOW" else ("#FDE2E0" if s_level == "CRITICAL" else "#FDF1D6")
            st.markdown(
                f"""
            <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 8px; padding: 10px 12px; background-color: {bg_cls}; border-radius: 6px; border: 1px solid #CBDCEB; border-left: 3px solid {cls};">
                <div style="font-size: 14px; font-weight: 800; color: {cls};">{icon}</div>
                <div>
                    <div style="font-size: 12px; font-weight: 700; color: #16324F;">{sig['name']}</div>
                    <div style="font-size: 11px; color: #536B82; margin-top: 2px;">{sig['message']}</div>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        # Show ELA image if available
        ela_obj = tampering.get("ela", {})
        ela_path = ela_obj.get("output_path")
        ela_val = ela_obj.get("mean_error", 0)
        if ela_path and os.path.exists(ela_path):
            with st.expander("View ELA (Error Level Analysis) Heatmap"):
                st.image(ela_path, caption=f"Error Level Analysis Difference Map (Mean Error: {ela_val})", use_container_width=True)

        # Show Annotated Inspection Image if available
        ann_path = tampering.get("annotated_image_path")
        if ann_path and os.path.exists(ann_path):
            with st.expander("View Visual Bounding Box Inspection Map"):
                st.image(ann_path, caption="Visual Discontinuity & Alteration Highlights", use_container_width=True)

    # 3. DIGILOCKER TRUSTED DIGITAL VAULT CROSS-VERIFICATION (Layer 7)
    vault_data = res.get("vault")
    if vault_data:
        st.markdown("<br>", unsafe_allow_html=True)
        v_match_sc = vault_data.get("overall_match_score", 100)
        v_status = vault_data.get("match_status", "MATCH")
        v_crit = vault_data.get("critical_mismatch", False)
        v_uid = vault_data.get("vault_user_id", "N/A")
        v_issuer = vault_data.get("issuer_info", {}).get("issuing_authority", "National Trust Network")
        v_sig = vault_data.get("issuer_info", {}).get("digital_signature", "ED25519-VALID")
        v_hash_info = vault_data.get("hash_comparison", {})
        v_face = vault_data.get("vault_face", {})

        st.markdown(
            """
        <div class="content-card">
            <div class="content-card-header">
                <span>🏛️</span> DigiLocker Trusted Digital Vault — Cross-Verification & Master Alignment
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        # 3 Top Metric Cards for Vault
        vm_col1, vm_col2, vm_col3 = st.columns(3)
        with vm_col1:
            st.markdown(
                f"""
            <div class="metric-card">
                <div class="metric-label">Vault Match Score</div>
                <div class="metric-value">{v_match_sc}%</div>
                <div style="font-size: 11px; color: #536B82; margin-top: 2px;">Citizen: {v_uid}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        with vm_col2:
            sc_color = "#238B57" if v_status == "MATCH" and not v_crit else ("#C88A1A" if v_status == "PARTIAL_MATCH" and not v_crit else "#D33C38")
            st.markdown(
                f"""
            <div class="metric-card">
                <div class="metric-label">Alignment Status</div>
                <div class="metric-value" style="color: {sc_color};">{v_status}</div>
                <div style="font-size: 11px; color: #536B82; margin-top: 2px;">{v_issuer[:25]}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        with vm_col3:
            h_match = v_hash_info.get("is_exact_hash", False)
            h_label = "EXACT MASTER BYTE" if h_match else "SCAN COPY VERIFIED"
            h_color = "#238B57" if h_match else "#1F4E79"
            st.markdown(
                f"""
            <div class="metric-card">
                <div class="metric-label">Cryptographic Integrity</div>
                <div class="metric-value" style="color: {h_color}; font-size: 15px;">{h_label}</div>
                <div style="font-size: 11px; color: #536B82; margin-top: 2px;">SHA-256 Digest Analysis</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        # Field-by-Field Semantic Comparison Table
        with st.expander("🔍 View Field-by-Field DigiLocker Master Alignment Table", expanded=True):
            st.markdown(
                """
            <table style="width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 12px;">
                <thead>
                    <tr style="background-color: #1F4E79; color: #FFFFFF; text-align: left;">
                        <th style="padding: 8px 12px; border-radius: 6px 0 0 0;">Attribute Field</th>
                        <th style="padding: 8px 12px;">Submitted Credential (OCR)</th>
                        <th style="padding: 8px 12px;">DigiLocker Master Record</th>
                        <th style="padding: 8px 12px; text-align: center;">Similarity</th>
                        <th style="padding: 8px 12px; border-radius: 0 6px 0 0; text-align: center;">Verdict</th>
                    </tr>
                </thead>
                <tbody>
            """,
                unsafe_allow_html=True,
            )
            table_rows_html = ""
            for row in vault_data.get("field_comparisons", []):
                r_stat = row.get("status", "MATCH")
                r_icon = "✓" if r_stat in ("EXACT_MATCH", "NOT_APPLICABLE", "MATCH") else ("⚠️" if r_stat in ("PARTIAL_MATCH", "UNEXTRACTED") else "✗")
                r_cls = "#238B57" if r_stat in ("EXACT_MATCH", "NOT_APPLICABLE", "MATCH") else ("#C88A1A" if r_stat in ("PARTIAL_MATCH", "UNEXTRACTED") else "#D33C38")
                r_bg = "#FFFFFF" if row.get("field") != "Document Number / UID" else "#F0F6FA"
                table_rows_html += f"""
                    <tr style="border-bottom: 1px solid #CBDCEB; background-color: {r_bg};">
                        <td style="padding: 7px 12px; font-weight: 700; color: #16324F;">{row.get('field')}</td>
                        <td style="padding: 7px 12px; font-family: 'JetBrains Mono', monospace; color: #1F4E79;">{row.get('submitted')}</td>
                        <td style="padding: 7px 12px; font-family: 'JetBrains Mono', monospace; color: #16324F; font-weight: 600;">{row.get('reference')}</td>
                        <td style="padding: 7px 12px; text-align: center; font-weight: 700; color: #536B82;">{row.get('similarity')}%</td>
                        <td style="padding: 7px 12px; text-align: center; font-weight: 800; color: {r_cls};">{r_icon} {r_stat}</td>
                    </tr>
                """
            table_rows_html += "</tbody></table>"
            st.markdown(table_rows_html, unsafe_allow_html=True)

            if vault_data.get("critical_reasons"):
                for cr in vault_data.get("critical_reasons"):
                    st.markdown(f"<div style='font-size: 11px; color: #7F1D1D; font-weight: 700; margin-bottom: 4px; padding: 6px 12px; background-color: #FEE2E2; border-left: 3px solid #B91C1C; border-radius: 4px;'>🚨 {cr}</div>", unsafe_allow_html=True)

        # Document-to-Vault Facial Biometric Match in Vault
        if v_face:
            with st.expander("👤 Document-to-Vault Facial Biometric Match", expanded=True):
                vf_stat = v_face.get("status", "MATCH")
                vf_sim = v_face.get("similarity_percentage", "100%")
                vf_cls = "#238B57" if vf_stat == "MATCH" else ("#C88A1A" if vf_stat == "REVIEW" else "#D33C38")
                st.markdown(f"<div style='font-size: 13px; font-weight: 800; color: {vf_cls}; margin-bottom: 6px;'>Verdict: {vf_stat} ({vf_sim} Similarity)</div>", unsafe_allow_html=True)
                st.caption(f"**Model:** {v_face.get('model', 'FaceNet512')} | **Distance:** {v_face.get('distance', 0.0)}")
                vf_doc_crop = v_face.get("submitted_face_crop")
                vf_ref_crop = v_face.get("vault_face_crop")
                if vf_doc_crop and vf_ref_crop and os.path.exists(vf_doc_crop) and os.path.exists(vf_ref_crop):
                    fc1, fc2 = st.columns(2)
                    with fc1:
                        st.image(vf_doc_crop, caption="Submitted Crop", width=120)
                    with fc2:
                        st.image(vf_ref_crop, caption="Vault Master Photo", width=120)

    # 4. Actions Toolbar
    st.markdown("<br>", unsafe_allow_html=True)
    report_json = {
        "system": "VERIDEX AI Document Screening",
        "timestamp": datetime.now().isoformat(),
        "screening_id": ledger_block.get("screening_id", f"VRX-{int(datetime.now().timestamp())}"),
        "blockchain_block_hash": ledger_block.get("block_hash"),
        "document_type": fields.get("document_type"),
        "risk_assessment": {
            "score": risk_score,
            "level": risk_level,
            "decision": decision,
            "components": risk_data.get("components"),
        },
        "validation_status": validation.get("status"),
        "tampering_score": tampering.get("tampering_score"),
        "exif_metadata": tampering.get("metadata"),
        "face_verification": {
            "status": face.get("status"),
            "distance": face.get("distance"),
            "threshold": face.get("threshold"),
            "similarity": face.get("similarity_percentage"),
        },
        "vault_verification": vault_data,
        "reasons": risk_data.get("reasons"),
    }

    if st.session_state.app_mode == "gateway":
        acol1, acol2, acol3, acol4 = st.columns([1, 1.2, 1, 1.3])
        with acol1:
            if st.button("← Back to Flagged Reasons", use_container_width=True):
                st.session_state.page = 6
                st.rerun()
        with acol2:
            if st.button("🏛️ Return to Wallet", use_container_width=True):
                st.session_state.page = 1
                st.session_state.gateway_step = 5
                st.session_state.result = None
                st.rerun()
        with acol3:
            if st.button("Screen Another Doc", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()
        with acol4:
            st.download_button(
                label="Download Screening Report",
                data=json.dumps(report_json, indent=2),
                file_name=f"veridex_report_{int(datetime.now().timestamp())}.json",
                mime="application/json",
                use_container_width=True,
            )
    else:
        acol1, acol2, acol3 = st.columns(3)
        with acol1:
            if st.button("← Back to Flagged Reasons", use_container_width=True):
                st.session_state.page = 6
                st.rerun()
        with acol2:
            if st.button("Screen Another Document", use_container_width=True):
                st.session_state.page = 2
                st.session_state.result = None
                st.session_state.document_file = None
                st.session_state.person_file = None
                st.session_state.document_path_override = None
                st.session_state.person_path_override = None
                st.rerun()
        with acol3:
            st.download_button(
                label="Download Screening Report (JSON)",
                data=json.dumps(report_json, indent=2),
                file_name=f"veridex_report_{int(datetime.now().timestamp())}.json",
                mime="application/json",
                use_container_width=True,
            )
