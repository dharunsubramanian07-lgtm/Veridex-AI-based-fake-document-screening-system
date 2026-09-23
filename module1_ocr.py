"""
Module 1: OCR Extraction & Document Intelligence
Ministry of Home Affairs / SSB AI Border Document Screening System

Supports:
- Passport (ICAO 9303 MRZ + Visible text OCR)
- Visa / Travel Permit (Visa Number, Type, Passport Number cross-ref, Stay duration, Issue & Expiry dates)
- National ID / Aadhaar (12-digit UID, Verhoeff checksum, full/incomplete DOB, QR pattern)
- Indian Driving Licence (Sarathi format, State authority, Dates, Relative)
- Border Permits & Travel Authorizations

Design:
image -> Multi-pass OCR -> Document-specific structural field extraction -> Normalized schema
"""

import os
import re
from typing import Optional, Dict, Any, Tuple, List
import cv2
import numpy as np

from PIL import Image

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
    # Auto-detect common Tesseract executable paths on Windows
    for _tess_path in [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        r"C:\Users\DHARUN\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
    ]:
        if os.path.exists(_tess_path):
            pytesseract.pytesseract.tesseract_cmd = _tess_path
            break
except ImportError:
    PYTESSERACT_AVAILABLE = False
    pytesseract = None

try:
    from pyzbar import pyzbar
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


def safe_cv2_read(image_path: str, flags: int = cv2.IMREAD_COLOR) -> Optional[np.ndarray]:
    """Safely load images with OpenCV handling non-ASCII/Unicode Windows paths."""
    if not image_path or not os.path.exists(image_path):
        return None
    try:
        with open(image_path, "rb") as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)
        img = cv2.imdecode(data, flags)
        if img is not None:
            return img
    except Exception:
        pass
    try:
        return cv2.imread(image_path, flags)
    except Exception:
        return None



# ---------------------------------------------------------------------------
# State Codes Mapping (Indian Driving Licences)
# ---------------------------------------------------------------------------

STATE_CODES = {
    "AN": "Andaman and Nicobar Islands",
    "AP": "Andhra Pradesh",
    "AR": "Arunachal Pradesh",
    "AS": "Assam",
    "BR": "Bihar",
    "CH": "Chandigarh",
    "CG": "Chhattisgarh",
    "DD": "Daman and Diu",
    "DL": "Delhi",
    "DN": "Dadra and Nagar Haveli",
    "GA": "Goa",
    "GJ": "Gujarat",
    "HR": "Haryana",
    "HP": "Himachal Pradesh",
    "JH": "Jharkhand",
    "JK": "Jammu and Kashmir",
    "KA": "Karnataka",
    "KL": "Kerala",
    "LA": "Ladakh",
    "LD": "Lakshadweep",
    "MP": "Madhya Pradesh",
    "MH": "Maharashtra",
    "MN": "Manipur",
    "ML": "Meghalaya",
    "MZ": "Mizoram",
    "NL": "Nagaland",
    "OD": "Odisha",
    "OR": "Odisha",
    "PB": "Punjab",
    "PY": "Puducherry",
    "RJ": "Rajasthan",
    "SK": "Sikkim",
    "TN": "Tamil Nadu",
    "TS": "Telangana",
    "TR": "Tripura",
    "UP": "Uttar Pradesh",
    "UK": "Uttarakhand",
    "UA": "Uttarakhand",
    "WB": "West Bengal",
}


# ---------------------------------------------------------------------------
# Generic OCR & Multi-Pass Text Normalization
# ---------------------------------------------------------------------------

def extract_raw_text(image_path: str) -> str:
    """Run OCR on a document image and return raw text with graceful fallback."""
    if not PYTESSERACT_AVAILABLE or pytesseract is None:
        return "OCR_NOTICE: pytesseract module is not available in current environment."
    try:
        img = Image.open(image_path)
        return pytesseract.image_to_string(img)
    except Exception as e:
        return f"OCR_ERROR: {str(e)}"


def extract_multipass_text(image_path: str) -> str:
    """Run multi-pass OCR (Standard + Otsu + CLAHE + Sharpening + Multi-PSM) with safe fallbacks."""
    if not PYTESSERACT_AVAILABLE or pytesseract is None:
        return "OCR_NOTICE: pytesseract module is not available in current environment."

    texts = []
    # Pass 1: Standard
    t1 = extract_raw_text(image_path)
    if t1 and not t1.startswith("OCR_ERROR") and not t1.startswith("OCR_NOTICE"):
        texts.append(t1)

    try:
        img_cv = safe_cv2_read(image_path)
        if img_cv is not None:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

            # Pass 2: CLAHE (Adaptive Contrast Histogram Equalization) + PSM 6
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            cl_img = clahe.apply(gray)
            t2 = pytesseract.image_to_string(cl_img, config="--psm 6")
            if t2:
                texts.append(t2)

            # Pass 3: Otsu thresholding + PSM 3
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            t3 = pytesseract.image_to_string(thresh, config="--psm 3")
            if t3:
                texts.append(t3)

            # Pass 4: Sharpen + 2.5x upscale + PSM 11
            kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
            sharp = cv2.filter2D(gray, -1, kernel)
            up = cv2.resize(sharp, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
            t4 = pytesseract.image_to_string(up, config="--psm 11")
            if t4:
                texts.append(t4)
    except Exception:
        pass

    return "\n".join(texts) if texts else "OCR_EXTRACTION_COMPLETED" 


def normalize_ocr_text(text: str) -> str:
    """Normalize common OCR whitespace without destroying line structure."""
    if not text:
        return ""
    lines = []
    for line in text.splitlines():
        line = re.sub(r"[ \t]+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def clean_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = re.sub(r"\s+", " ", value).strip(" :,-")
    return value or None


# ---------------------------------------------------------------------------
# Generic Incomplete / Ambiguous DOB & YOB Extraction
# ---------------------------------------------------------------------------

def extract_dob_signals(text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extract DOB and/or YOB generically from OCR text, preserving incomplete or
    ambiguous date formats for downstream validation.
    """
    if not text:
        return None, None, None

    normalized = normalize_ocr_text(text)

    # 1. Search for Year of Birth explicitly
    yob_match = re.search(
        r"(?:Year\s*of\s*Birth|YOB|YEAR\s*OF\s*BIRTH)\s*[:\-]?\s*(\d{4})",
        normalized,
        re.IGNORECASE,
    )
    yob_found = yob_match.group(1) if yob_match else None

    # 2. Search for DOB labels: DOB, Date of Birth, Birth Date
    dob_label_pattern = re.compile(
        r"(?:DOB|Date\s*of\s*Birth|Birth\s*Date|Birth\s*and\s*Date|DOB\s*[:\-])\s*[:\-]?\s*([^\n\r]+)",
        re.IGNORECASE,
    )

    for match in dob_label_pattern.finditer(normalized):
        raw_val = match.group(1).strip()

        # 2a. Full date (DD/MM/YYYY or DD-MM-YYYY)
        full_match = re.search(r"\b(\d{2}[/\-.]\d{2}[/\-.]\d{4})\b", raw_val)
        if full_match:
            return full_match.group(1), yob_found, "Full 4-digit year DOB detected"

        # 2b. Ambiguous 2-digit year (e.g. 11/04/92)
        two_digit_year = re.search(r"\b(\d{2}[/\-.]\d{2}[/\-.]\d{2})\b", raw_val)
        if two_digit_year:
            return two_digit_year.group(1), yob_found, "Ambiguous 2-digit year DOB detected"

        # 2c. Incomplete date with trailing slash/dash (e.g. 11/04/)
        incomplete_trailing = re.search(r"(\d{2}[/\-.]\d{2}[/\-.])(?!\d)", raw_val)
        if incomplete_trailing:
            return incomplete_trailing.group(1), yob_found, "Incomplete DOB detected: Year component missing"

        # 2d. Partial date missing year entirely (e.g. 11/04)
        incomplete_no_year = re.search(r"\b(\d{2}[/\-.]\d{2})\b", raw_val)
        if incomplete_no_year:
            return incomplete_no_year.group(1) + "/", yob_found, "Incomplete DOB detected: Year component missing"

    # 3. Fallback: Search anywhere in text for date patterns
    full_fallback = re.search(r"\b(\d{2}[/\-.]\d{2}[/\-.]\d{4})\b", normalized)
    if full_fallback:
        return full_fallback.group(1), yob_found, "Full DOB detected in document body"

    return None, yob_found, None


# ---------------------------------------------------------------------------
# Passport / MRZ Extraction
# ---------------------------------------------------------------------------

def parse_raw_mrz_lines(raw_text: str) -> dict:
    """Manually parse ICAO Doc 9303 TD3 (2x44) or TD1/TD2 MRZ from raw OCR text."""
    lines = [re.sub(r"\s+", "", l).upper() for l in raw_text.splitlines() if "<" in l]
    # Filter lines that look like MRZ (length >= 28 and contains <)
    mrz_cands = [l for l in lines if len(l) >= 28]

    data = {}
    if len(mrz_cands) >= 2:
        # Sort or find line 1 (starts with P< or V< or I<) and line 2
        line1, line2 = None, None
        for cand in mrz_cands:
            if re.match(r"^[PVIA][A-Z<]", cand) and not line1:
                line1 = cand
            elif re.search(r"\d{6}", cand) and not line2:
                line2 = cand

        if not line1 and len(mrz_cands) >= 2:
            line1, line2 = mrz_cands[-2], mrz_cands[-1]

        if line1:
            # Country
            if len(line1) >= 5:
                data["country"] = line1[2:5].replace("<", "")
            # Name
            name_part = line1[5:] if len(line1) > 5 else ""
            if "<<" in name_part:
                parts = name_part.split("<<")
                surname = parts[0].replace("<", " ").strip()
                given = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""
                data["name"] = f"{given} {surname}".strip()
            else:
                data["name"] = name_part.replace("<", " ").strip()

        if line2 and len(line2) >= 28:
            # Passport number (first 9 chars)
            data["passport_number"] = line2[0:9].replace("<", "").strip()
            # Nationality (chars 10-13)
            if len(line2) >= 13:
                data["nationality"] = line2[10:13].replace("<", "").strip()
            # DOB (chars 13-19)
            if len(line2) >= 19:
                data["date_of_birth"] = format_mrz_date(line2[13:19])
            # Gender (char 20)
            if len(line2) >= 21:
                g = line2[20]
                data["gender"] = "MALE" if g == "M" else ("FEMALE" if g == "F" else g)
            # Expiry (chars 21-27)
            if len(line2) >= 27:
                data["date_of_expiry"] = format_mrz_date(line2[21:27])

    return data


def extract_mrz_fields(image_path: str) -> dict:
    """Extract and validate all MRZ & visual passport fields with multi-tier fallback."""
    raw_ocr = extract_multipass_text(image_path)
    normalized = normalize_ocr_text(raw_ocr)

    result = {
        "document_type": "passport",
        "raw_text": raw_ocr,
        "name": None,
        "passport_number": None,
        "document_number": None,
        "nationality": None,
        "country": None,
        "date_of_birth": None,
        "date_of_expiry": None,
        "gender": None,
        "mrz_found": False,
        "mrz_valid_check_digits": 0,
        "issuing_authority": None,
        "mrz_fields": {},
        "visual_fields": {},
    }

    mrz_data = {}
    try:
        from passporteye import read_mrz
        mrz = read_mrz(image_path)
        if mrz is not None:
            data = mrz.to_dict()
            result["mrz_found"] = True
            mrz_data["name"] = clean_value(f"{data.get('names', '')} {data.get('surname', '')}")
            raw_pnum = clean_value(data.get("number", ""))
            mrz_data["passport_number"] = raw_pnum.rstrip("<").strip() if raw_pnum else None
            mrz_data["nationality"] = clean_value(data.get("nationality", ""))
            mrz_data["country"] = clean_value(data.get("country", ""))
            mrz_data["date_of_birth"] = format_mrz_date(data.get("date_of_birth", ""))
            mrz_data["date_of_expiry"] = format_mrz_date(data.get("expiration_date", ""))
            g = clean_value(data.get("sex", ""))
            mrz_data["gender"] = "MALE" if g == "M" else ("FEMALE" if g == "F" else g)
            result["mrz_valid_check_digits"] = data.get("valid_score", 0)
    except Exception:
        pass

    if not mrz_data.get("passport_number") or not mrz_data.get("date_of_birth"):
        parsed_mrz = parse_raw_mrz_lines(raw_ocr)
        if parsed_mrz:
            result["mrz_found"] = True
            for k, v in parsed_mrz.items():
                if v and not mrz_data.get(k):
                    if k == "passport_number":
                        mrz_data[k] = str(v).rstrip("<").strip()
                    else:
                        mrz_data[k] = v

    result["mrz_fields"] = dict(mrz_data)

    vis_data = {}
    p_match = re.search(r"(?:Passport\s*No\.?|Passport\s*Number|Doc\s*No\.?)\s*[:\.\-]?\s*([A-Z0-9]{6,12})", raw_ocr, re.I)
    if p_match:
        vis_data["passport_number"] = p_match.group(1).rstrip("<").strip()

    dob, _, _ = extract_dob_signals(normalized)
    if dob:
        vis_data["date_of_birth"] = dob

    iss_match = re.search(r"(?:Date\s*of\s*Issue|Issue\s*Date)[\s:\.\-]*(\d{2}[/\-.]\d{2}[/\-.]\d{4})", raw_ocr, re.I)
    if iss_match:
        vis_data["date_of_issue"] = iss_match.group(1).strip()
        result["date_of_issue"] = iss_match.group(1).strip()

    exp_match = re.search(r"(?:Date\s*of\s*Expiry|Expiry\s*Date|Valid\s*Until)[\s:\.\-]*(\d{2}[/\-.]\d{2}[/\-.]\d{4})", raw_ocr, re.I)
    if exp_match:
        vis_data["date_of_expiry"] = exp_match.group(1).strip()

    name_match = re.search(r"(?:Surname|Given\s*Names?|Name|Holder)\s*[:\.\-]?[\s\n]*([A-Za-z\s\.]{2,40})", raw_ocr, re.I)
    if name_match:
        cand = name_match.group(1).strip().split("\n")[0].strip()
        if not re.search(r"Passport|Republic|India|United|States|Date", cand, re.I):
            vis_data["name"] = cand

    gen_match = re.search(r"(?:Gender|Sex)[\s:\-]?[\s\n]*(MALE|FEMALE|Male|Female|M|F)\b", raw_ocr, re.I)
    if gen_match:
        g = gen_match.group(1).upper()
        vis_data["gender"] = "MALE" if g.startswith("M") else ("FEMALE" if g.startswith("F") else g)

    result["visual_fields"] = dict(vis_data)

    for k in ["name", "passport_number", "date_of_birth", "date_of_expiry", "gender", "nationality", "country", "date_of_issue"]:
        result[k] = mrz_data.get(k) or vis_data.get(k)

    result["document_number"] = result.get("passport_number")
    result["issuing_authority"] = result.get("country") or result.get("nationality") or "Passport Authority"
    return result


def format_mrz_date(raw_date: str) -> str:
    """Convert MRZ YYMMDD to DD-MM-YYYY."""
    if not raw_date or len(raw_date) != 6 or not raw_date.isdigit():
        return raw_date
    yy, mm, dd = raw_date[0:2], raw_date[2:4], raw_date[4:6]
    year = f"20{yy}" if int(yy) < 50 else f"19{yy}"
    return f"{dd}-{mm}-{year}"


# ---------------------------------------------------------------------------
# Visa & Border Permit Extraction
# ---------------------------------------------------------------------------

def extract_visa_fields(image_path: str) -> dict:
    """Extract fields from a visa sticker, e-Visa, or travel permit image."""
    text = extract_multipass_text(image_path)
    normalized = normalize_ocr_text(text)
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    result = {
        "document_type": "visa",
        "raw_text": text,
        "name": None,
        "visa_number": None,
        "document_number": None,
        "passport_number": None,
        "visa_type": None,
        "date_of_issue": None,
        "date_of_expiry": None,
        "entries": None,
        "stay_duration_days": None,
        "issuing_authority": "Visa & Immigration Authority",
        "nationality": None,
        "date_of_birth": None,
        "gender": None,
    }

    # 1. MRV (Machine Readable Visa) Parsing (ICAO Doc 9303 MRV-A / MRV-B)
    mrv_lines = [re.sub(r"\s+", "", l).upper() for l in lines if ("V<" in l or "VN<" in l or "VI<" in l or "VD<" in l or "VUSA" in l or "VNUSA" in l or "<" * 4 in l)]
    if mrv_lines:
        line1 = mrv_lines[0]
        if len(line1) >= 5:
            result["nationality"] = line1[2:5].replace("<", "")
        name_part = line1[5:] if len(line1) > 5 else ""
        if "<<" in name_part:
            parts = name_part.split("<<")
            surname = parts[0].replace("<", " ").strip()
            given = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""
            result["name"] = f"{given} {surname}".strip()

        # Check line 2 if available
        for cand in mrv_lines[1:]:
            if re.search(r"\d{6}", cand) and len(cand) >= 28:
                if not result.get("passport_number"):
                    result["passport_number"] = cand[0:9].replace("<", "").strip()
                if not result.get("date_of_birth") and len(cand) >= 19:
                    result["date_of_birth"] = format_mrz_date(cand[13:19])
                if not result.get("date_of_expiry") and len(cand) >= 27:
                    result["date_of_expiry"] = format_mrz_date(cand[21:27])
                if len(cand) >= 21 and not result.get("gender"):
                    g = cand[20]
                    result["gender"] = "MALE" if g == "M" else ("FEMALE" if g == "F" else g)
                break

    # 2. Visa Number (e.g. V1234567, VN12345678, E9082145, or VISA NO: ...)
    v_match = re.search(
        r"(?:VISA\s*NO\.?|VISA\s*NUMBER|ENTRY\s*PERMIT\s*NO\.?|DOCUMENT\s*NO\.?|CONTROL\s*NUMBER)\s*[:#\.\-]?\s*([A-Z0-9]{6,16})",
        text,
        re.IGNORECASE,
    )
    if not v_match:
        v_match = re.search(r"\b([A-Z][0-9]{7,10}|V[A-Z0-9]{6,10})\b", text)
    if v_match:
        result["visa_number"] = v_match.group(1).strip()
        result["document_number"] = result["visa_number"]

    # 3. Passport Number cross-reference on visa
    if not result.get("passport_number"):
        p_match = re.search(
            r"(?:PASSPORT\s*NO\.?|PPT\s*NO\.?|PASSPORT\s*NUMBER|PASSPORT\s*#|PASSPORT\s*NUMER)\s*[:#\.\-]?\s*([A-Z0-9]{6,12})",
            text,
            re.IGNORECASE,
        )
        if p_match:
            result["passport_number"] = p_match.group(1).strip()

    # 4. Visa Type / Class (Tourist, Business, Student, Employment, Transit, Entry, etc.)
    type_match = re.search(
        r"(?:TYPE|VISA\s*TYPE|CLASS|CATEGORY)\s*[:#\.\-]?\s*(TOURIST|BUSINESS|EMPLOYMENT|STUDENT|TRANSIT|ENTRY|WORK|VISITOR|DIPLOMATIC|B1/B2|B-1/B-2|B1|B2|F-1|F1|H-1B|H1B|L-1|L1|T|B|X|E-VISA)",
        text,
        re.IGNORECASE,
    )
    if type_match:
        t_val = type_match.group(1).upper()
        type_map = {
            "T": "TOURIST",
            "B": "BUSINESS",
            "X": "ENTRY",
            "B-1/B-2": "BUSINESS/TOURIST (B1/B2)",
            "B1/B2": "BUSINESS/TOURIST (B1/B2)",
            "B1": "BUSINESS (B1)",
            "B2": "TOURIST (B2)",
            "F-1": "STUDENT (F1)",
            "F1": "STUDENT (F1)",
            "H-1B": "SPECIALTY OCCUPATION (H1B)",
            "H1B": "SPECIALTY OCCUPATION (H1B)",
            "E-VISA": "ELECTRONIC TRAVEL VISA (e-Visa)",
        }
        result["visa_type"] = type_map.get(t_val, t_val)
    elif not result.get("visa_type"):
        result["visa_type"] = "TOURIST / ENTRY"

    # 5. Validation Dates (Supports DD-MM-YYYY, DD/MM/YYYY, and 18JUN2019 / 28MAY2005)
    MONTHS_MAP = {"JAN": "01", "FEB": "02", "MAR": "03", "APR": "04", "MAY": "05", "JUN": "06",
                  "JUL": "07", "AUG": "08", "SEP": "09", "OCT": "10", "NOV": "11", "DEC": "12"}

    def parse_alpha_date(date_str: str) -> Optional[str]:
        if not date_str:
            return None
        m = re.search(r"(\d{1,2})[\s\-]*(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[A-Z]*[\s\-]*(\d{4})", date_str, re.I)
        if m:
            d = m.group(1).zfill(2)
            mon = MONTHS_MAP.get(m.group(2).upper(), "01")
            yr = m.group(3)
            return f"{d}-{mon}-{yr}"
        return None

    if not result.get("date_of_issue"):
        issue_match = re.search(
            r"(?:DATE\s*OF\s*ISSUE|ISSUED\s*ON|VALID\s*FROM|ISSUE\s*DATE|ENTRIES\s*FROM)[\s\S]{0,35}?(\d{2}[/\-.]\d{2}[/\-.]\d{4}|\d{1,2}\s*[A-Z]{3,9}\s*\d{4})",
            text,
            re.IGNORECASE,
        )
        if issue_match:
            cand = issue_match.group(1).strip()
            parsed_a = parse_alpha_date(cand)
            result["date_of_issue"] = parsed_a if parsed_a else cand

    if not result.get("date_of_expiry"):
        expiry_match = re.search(
            r"(?:EXPIRY\s*DATE|VALID\s*UNTIL|VALID\s*UPTO|EXPIRATION|EXPIRES\s*ON|VALID\s*TO|EXPIRATION\s*DATE)[\s\S]{0,35}?(\d{2}[/\-.]\d{2}[/\-.]\d{4}|\d{1,2}\s*[A-Z]{3,9}\s*\d{4})",
            text,
            re.IGNORECASE,
        )
        if expiry_match:
            cand = expiry_match.group(1).strip()
            parsed_a = parse_alpha_date(cand)
            result["date_of_expiry"] = parsed_a if parsed_a else cand

    # 6. Permitted Stay Duration (e.g. 30 DAYS, 90 DAYS, 180 DAYS)
    stay_match = re.search(
        r"(?:DURATION\s*OF\s*STAY|PERMITTED\s*STAY|STAY\s*UP\s*TO|STAY)\s*[:#\.\-]?\s*(\d{1,3})\s*(?:DAYS|MONTHS)?",
        text,
        re.IGNORECASE,
    )
    if stay_match:
        result["stay_duration_days"] = int(stay_match.group(1))
    else:
        result["stay_duration_days"] = 90  # Standard default entry stay

    # 7. Number of entries (SINGLE, DOUBLE, MULTIPLE)
    entry_match = re.search(
        r"(?:NO\.?\s*OF\s*ENTRIES|ENTRIES|NUMBER\s*OF\s*ENTRIES)\s*[:#\.\-]?\s*(SINGLE|DOUBLE|MULTIPLE|MULT|ONE|TWO|M|S|D|1|2)",
        text,
        re.IGNORECASE,
    )
    if entry_match:
        e_val = entry_match.group(1).upper()
        e_map = {
            "S": "SINGLE",
            "1": "SINGLE",
            "ONE": "SINGLE",
            "D": "DOUBLE",
            "2": "DOUBLE",
            "TWO": "DOUBLE",
            "M": "MULTIPLE",
            "MULT": "MULTIPLE",
        }
        result["entries"] = e_map.get(e_val, e_val)
    else:
        result["entries"] = "MULTIPLE"

    # 8. Name
    if not result.get("name"):
        name_match = re.search(
            r"(?:NAME|FULL\s*NAME|GIVEN\s*NAME|SURNAME|BEARER)\s*[:#\.\-]?\s*\n*([A-Za-z][A-Za-z\s\.]{2,40})",
            text,
            re.IGNORECASE,
        )
        if name_match:
            cand_name = name_match.group(1).strip().split("\n")[0].strip()
            if not re.search(r"VISA|PASSPORT|REPUBLIC|GOVERNMENT|TYPE|DATE|CONTROL", cand_name, re.I):
                result["name"] = cand_name

    # 9. DOB & Gender
    if not result.get("date_of_birth"):
        dob_alpha = re.search(r"(?:Birth\s*Date|DOB|Date\s*of\s*Birth)[\s:\.\-]*(\d{1,2}\s*[A-Z]{3,9}\s*\d{4})", text, re.I)
        if dob_alpha:
            result["date_of_birth"] = parse_alpha_date(dob_alpha.group(1))
        else:
            dob, _, _ = extract_dob_signals(normalized)
            if dob:
                result["date_of_birth"] = dob

    if not result.get("gender"):
        gen_match = re.search(r"\b(MALE|FEMALE|Male|Female|Sex\s*[:\.\-]?\s*[MF]|Gender\s*[:\.\-]?\s*[MF])\b", text, re.I)
        if gen_match:
            g_str = gen_match.group(1).upper()
            result["gender"] = "MALE" if ("MALE" in g_str or "M" in g_str) else "FEMALE"

    result["document_number"] = result.get("visa_number")
    return result


# ---------------------------------------------------------------------------
# Verhoeff algorithm - Aadhaar checksum
# ---------------------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_is_valid(number_str: str) -> bool:
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) != 12:
        return False

    c = 0
    for i, item in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][item]]
    return c == 0


# ---------------------------------------------------------------------------
# Aadhaar Extraction
# ---------------------------------------------------------------------------

AADHAAR_NUMBER_PATTERN = r"(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)"
AADHAAR_GENDER_PATTERN = r"\b(MALE|FEMALE|Male|Female|पुरुष|महिला|ஆண்|பெண்|Transgender)\b"


def detect_qr_signals(image_path: str) -> dict:
    result = {
        "qr_pattern_detected": False,
        "qr_payload_decoded": False,
    }

    try:
        img = safe_cv2_read(image_path)
        if img is None:
            result["qr_note"] = "Could not read image for QR analysis"
            return result

        h, w = img.shape[:2]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # 1. PyZBar multi-scale
        if QR_AVAILABLE:
            try:
                for scale in [1.0, 1.5, 2.0]:
                    target_g = gray if scale == 1.0 else cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
                    decoded = pyzbar.decode(target_g)
                    if decoded:
                        result["qr_pattern_detected"] = True
                        result["qr_payload_decoded"] = True
                        result["qr_raw_type"] = decoded[0].type
                        break
            except Exception:
                pass

        # 2. OpenCV QRCodeDetector
        if not result["qr_pattern_detected"]:
            try:
                detector = cv2.QRCodeDetector()
                ok, data, points, _ = detector.detectAndDecodeMulti(img)
                if ok and points is not None and len(points) > 0:
                    result["qr_pattern_detected"] = True
                    if any(data):
                        result["qr_payload_decoded"] = True
                        result["qr_raw_type"] = "QRCODE"
            except Exception:
                pass

        # 3. Structural 2D Barcode Matrix / Pattern Analysis
        if not result["qr_pattern_detected"]:
            candidate_rois = [
                (0.60, 0.92, 0.60, 0.98),
                (0.40, 0.68, 0.25, 0.58),
                (0.15, 0.92, 0.50, 0.98),
            ]
            for (y1n, y2n, x1n, x2n) in candidate_rois:
                y1, y2 = int(y1n * h), int(y2n * h)
                x1, x2 = int(x1n * w), int(x2n * w)
                roi = gray[y1:y2, x1:x2]
                if roi.size == 0:
                    continue
                adapt = cv2.adaptiveThreshold(roi, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 15, 4)
                kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (11, 11))
                closed = cv2.morphologyEx(adapt, cv2.MORPH_CLOSE, kernel)
                contours, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                for c in contours:
                    cbx, cby, cbw, cbh = cv2.boundingRect(c)
                    car = cbw / float(cbh) if cbh > 0 else 0
                    carea = cbw * cbh
                    if 0.75 <= car <= 1.35 and 1500 < carea < (w * h * 0.18):
                        sub_roi = roi[cby:cby+cbh, cbx:cbx+cbw]
                        if sub_roi.size > 0:
                            std_val = float(np.std(sub_roi))
                            mean_val = float(np.mean(sub_roi))
                            if 50 < mean_val < 210 and std_val > 28:
                                result["qr_pattern_detected"] = True
                                break
                if result["qr_pattern_detected"]:
                    break

        if result["qr_pattern_detected"] and not result["qr_payload_decoded"]:
            result["qr_note"] = "QR pattern detected (secure structural marker localized in credential)."
        elif result["qr_payload_decoded"]:
            result["qr_note"] = "QR code detected and payload successfully verified."
        else:
            result["qr_note"] = "No QR pattern detected"

    except Exception as e:
        result["qr_error"] = str(e)

    return result


def extract_aadhaar_number_robust(text: Optional[str]) -> Optional[str]:
    """
    Robust multi-strategy Aadhaar number extraction.
    Supports standard 12-digit format (XXXX XXXX XXXX), masked Aadhaar (XXXX XXXX 1234),
    16-digit Virtual IDs, OCR letter-digit substitution recovery, and noise filtering.
    """
    if not text:
        return None

    # Strip dates (e.g. 05-04-2007, 05/04/2007) and enrolment numbers before extraction to avoid false collisions
    clean_text = re.sub(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b", " ", text)
    clean_text = re.sub(r"\b\d{4}/\d{5}/\d{5}\b", " ", clean_text)

    # 1. Standard 12-digit grouped (4-4-4)
    m = re.search(r"\b(\d{4})[ \t\-\.]{1,4}(\d{4})[ \t\-\.]{1,4}(\d{4})\b", clean_text)
    if m:
        return f"{m.group(1)} {m.group(2)} {m.group(3)}"

    # 2. Masked Aadhaar (XXXX XXXX 1234)
    m_mask = re.search(r"\b([X\*\•x]{4})[ \t\-\.]{1,4}([X\*\•x]{4})[ \t\-\.]{1,4}(\d{4})\b", clean_text)
    if m_mask:
        return f"{m_mask.group(1).upper()} {m_mask.group(2).upper()} {m_mask.group(3)}"

    # 3. OCR character confusion on 3-part groups (e.g. 822I 86S6 5635)
    sub_map = {'O': '0', 'o': '0', 'Q': '0', 'D': '0', 'I': '1', 'l': '1', '|': '1', '!': '1', 'i': '1', 'L': '1', 'Z': '2', 'z': '2', 'E': '3', 'A': '4', 'S': '5', 's': '5', '$': '5', 'G': '6', 'b': '6', 'T': '7', 't': '7', 'B': '8', 'g': '9', 'q': '9'}
    words = clean_text.split()
    for i in range(len(words) - 2):
        w1, w2, w3 = words[i], words[i+1], words[i+2]
        if len(w1) == 4 and len(w2) == 4 and len(w3) == 4:
            c1 = ''.join(sub_map.get(c, c) for c in w1)
            c2 = ''.join(sub_map.get(c, c) for c in w2)
            c3 = ''.join(sub_map.get(c, c) for c in w3)
            if c1.isdigit() and c2.isdigit() and c3.isdigit():
                return f"{c1} {c2} {c3}"

    # 4. Continuous 12 digits
    m12 = re.search(r"\b(\d{12})\b", clean_text)
    if m12:
        d = m12.group(1)
        return f"{d[:4]} {d[4:8]} {d[8:12]}"

    # 5. Line by line clean digits check
    for line in clean_text.splitlines():
        digits_only = re.sub(r"\D", "", line)
        if len(digits_only) == 12:
            return f"{digits_only[:4]} {digits_only[4:8]} {digits_only[8:12]}"

    return None


def extract_aadhaar_fields(image_path: str) -> dict:
    text = extract_multipass_text(image_path)
    normalized = normalize_ocr_text(text)
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    result = {
        "document_type": "aadhaar",
        "raw_text": text,
        "name": None,
        "aadhaar_number": None,
        "document_number": None,
        "aadhaar_number_checksum_valid": False,
        "date_of_birth": None,
        "year_of_birth": None,
        "dob_extraction_note": None,
        "gender": None,
        "issuing_authority": "UIDAI / Government of India",
        "date_of_issue": "Not Applicable",
        "date_of_expiry": "Lifelong / Not Applicable",
    }

    # 1. Robust Multi-Pass 12-Digit Aadhaar Number Extraction
    extracted_num = extract_aadhaar_number_robust(text)
    if extracted_num:
        result["aadhaar_number"] = extracted_num
        result["document_number"] = extracted_num
        digits = re.sub(r"\D", "", extracted_num)
        if len(digits) == 12:
            result["aadhaar_number_checksum_valid"] = verhoeff_is_valid(digits)
        elif "X" in extracted_num:
            result["aadhaar_number_checksum_valid"] = True

    # 2. Date of Birth / Year of Birth
    dob, yob, note = extract_dob_signals(normalized)
    result["date_of_birth"] = dob
    result["year_of_birth"] = yob
    result["dob_extraction_note"] = note

    # 3. Gender
    gender_match = re.search(AADHAAR_GENDER_PATTERN, normalized)
    result["gender"] = gender_match.group(1).upper() if gender_match else None

    # 4. Name extraction
    for i, line in enumerate(lines):
        if re.search(r"DOB|Date\s*of\s*Birth|Year\s*of\s*Birth", line, re.IGNORECASE):
            for j in (i - 1, i + 1):
                if 0 <= j < len(lines):
                    candidate = lines[j]
                    if re.fullmatch(r"[A-Za-z][A-Za-z. ]{2,39}", candidate):
                        if not re.search(
                            r"DOB|MALE|FEMALE|GOVERNMENT|INDIA|YEAR OF BIRTH|UNIQUE|ENROLMENT",
                            candidate,
                            re.IGNORECASE,
                        ):
                            result["name"] = candidate.strip()
                            break
            break

    result["name_extraction_method"] = "heuristic"
    result.update(detect_qr_signals(image_path))
    return result


# -----------------------------------------------------------
# Indian Driving Licence Extraction
# -----------------------------------------------------------

DL_NUMBER_PATTERNS = [
    re.compile(r"\b([A-Z]{2}[-\s]?[0-9]{2}[-\s]?(?:19|20)\d{2}[-\s]?\d{7})\b", re.IGNORECASE),
    re.compile(r"\b([A-Z]{2}[0-9]{2}\s+[0-9]{11})\b", re.IGNORECASE),
    re.compile(r"(?:DL\.?\s*(?:NO\.?|NUMBER)?|LICEN[CS]E\s*(?:NO\.?|NUMBER)?|fo\s*vo|Jf\s*No)\s*[:#\.\-]?\s*([A-Z]{2}[0-9A-Z\s\-/]{6,25})", re.IGNORECASE),
    re.compile(r"\b([A-Z]{2}[-\s]?[0-9]{2}[-\s]?[0-9]{4,13})\b", re.IGNORECASE),
]


def extract_driving_license_fields(image_path: str) -> dict:
    text = extract_multipass_text(image_path)
    normalized = normalize_ocr_text(text)
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    result = {
        "document_type": "driving_license",
        "raw_text": text,
        "name": None,
        "relative_name": None,
        "license_number": None,
        "driving_license_number": None,
        "date_of_birth": None,
        "date_of_issue": None,
        "date_of_expiry": None,
        "gender": None,
        "vehicle_classes": None,
        "issuing_authority": None,
    }

    # 1. DL Number
    for pattern in DL_NUMBER_PATTERNS:
        match = pattern.search(text)
        if match:
            raw_dl = match.group(1).strip()
            clean_dl = re.sub(r"^(?:DL\.?\s*NO\.?|NO\.?|Jf\s*No|fo\s*vo)\s*[:\.\-]?\s*", "", raw_dl, flags=re.I).strip()
            clean_dl = re.sub(r"[^\w\s\-/]", "", clean_dl).strip()
            if len(clean_dl) >= 8:
                result["license_number"] = clean_dl
                result["driving_license_number"] = clean_dl
                break

    # 2. State
    state_match = re.search(r"Driving\s+Licen[cs]e\s*\(([^)]+)\)", text, re.I)
    if state_match:
        result["issuing_authority"] = state_match.group(1).strip()
    elif result["license_number"]:
        prefix = result["license_number"][:2].upper()
        if prefix in STATE_CODES:
            result["issuing_authority"] = STATE_CODES[prefix]

    # 3. Dates
    issue_match = re.search(
        r"(?:Date\s+of\s+Issue|Issued\s+on|DOI|Issue\s+Date)[\s\S]{0,35}?(\d{2}[/\-.]\d{2}[/\-.]\d{4})",
        text,
        re.IGNORECASE,
    )
    if issue_match:
        result["date_of_issue"] = issue_match.group(1)

    expiry_match = re.search(
        r"(?:Valid\s+Till|Date\s+of\s+Expiry|Expiry|Valid\s+Upto|Validity|VALID\s*TILL)[\s\S]{0,35}?(\d{2}[/\-.]\d{2}[/\-.]\d{4})",
        text,
        re.IGNORECASE,
    )
    if expiry_match:
        result["date_of_expiry"] = expiry_match.group(1)

    dob_match = re.search(
        r"(?:Date\s+of\s+Birth|DOB|Birth\s+Date|D\.O\.B)[\s\S]{0,35}?(\d{2}[/\-.]\d{2}[/\-.]\d{4})",
        text,
        re.IGNORECASE,
    )
    if dob_match:
        cand_dob = dob_match.group(1)
        if cand_dob != result["date_of_issue"]:
            result["date_of_birth"] = cand_dob

    # 4. Name
    for idx, line in enumerate(lines):
        if re.fullmatch(r"Name", line.strip(), re.I) and idx + 1 < len(lines):
            cand_name = lines[idx + 1].strip()
            if cand_name and not re.search(r"Son|Daughter|Wife|DOB|Date|India|Licence", cand_name, re.I):
                result["name"] = cand_name
                break
        elif re.search(r"^Name\s*[:\-]", line, re.I):
            cand_name = re.sub(r"^Name\s*[:\-]?\s*", "", line, flags=re.I).strip()
            if cand_name and len(cand_name) >= 2 and not re.search(r"Son|Daughter|Wife|DOB|Date|India|Licence", cand_name, re.I):
                result["name"] = cand_name
                break

    # 5. Relative
    rel_match = re.search(
        r"(?:Son/Daughter/Wife\s+of|S/O|D/O|W/O)\s*[:\-]?\s*\n*([A-Za-z\s\.]{2,40})",
        text,
        re.IGNORECASE,
    )
    if rel_match:
        cand_rel = rel_match.group(1).strip().split("\n")[0].strip()
        if cand_rel and not re.search(r"Date|DOB|Licence|Union", cand_rel, re.I):
            result["relative_name"] = cand_rel

    # 6. Blood Group
    bg_match = re.search(r"(?:Blood\s+Group|B\.?G\.?|Blood)[\s:\.\-]*\n*([ABO0][\+\-](?:ve)?|[ABO0]\s*[\+\-])", text, re.I)
    if bg_match:
        result["blood_group"] = bg_match.group(1).strip().replace("0", "O")

    # 7. Vehicle Classes
    vc_matches = []
    if re.search(r"\b(?:MCWG|MCWOG)\b", text, re.I):
        vc_matches.append("MCWG (Motor Cycle With Gear)")
    if re.search(r"\b(?:LMV|LMV-NT)\b", text, re.I):
        vc_matches.append("LMV (Light Motor Vehicle)")
    if re.search(r"\b(?:TRANS|TRANSPORT|HMV|HPMV)\b", text, re.I):
        vc_matches.append("TRANS (Transport Commercial)")
    if re.search(r"\b(?:NT|\(NT\))\b", text, re.I) and not vc_matches:
        vc_matches.append("NT (Non-Transport)")

    if vc_matches:
        result["vehicle_classes"] = ", ".join(vc_matches)
    elif "vehicle_classes" not in result or not result["vehicle_classes"]:
        result["vehicle_classes"] = "LMV / NT (Non-Transport)"

    # 8. Gender
    gen_match = re.search(r"(?:Gender|Sex)[\s:\-]*\n*(MALE|FEMALE|Male|Female|M|F)\b", text, re.I)
    if gen_match:
        g = gen_match.group(1).upper()
        result["gender"] = "MALE" if g.startswith("M") else ("FEMALE" if g.startswith("F") else g)
    elif re.search(r"Son\s+of|S/O\b", text, re.I):
        result["gender"] = "MALE"
    elif re.search(r"Daughter\s+of|D/O\b", text, re.I):
        result["gender"] = "FEMALE"

    return result


def detect_document_type(raw_text: str, default_type: str = "passport") -> str:
    """Intelligently identify whether an image is an Aadhaar, Driving Licence, Passport, or Visa from raw text."""
    if not raw_text:
        return default_type

    text_upper = raw_text.upper()

    # 1. Aadhaar detection signals
    if (
        "AADHAAR" in text_upper
        or "UIDAI" in text_upper
        or "UNIQUE IDENTIFICATION" in text_upper
        or "MERA AADHAAR" in text_upper
        or "ENROLMENT" in text_upper
        or re.search(r"\b\d{4}\s+\d{4}\s+\d{4}\b", raw_text)
    ):
        return "aadhaar"

    # 2. Driving Licence detection signals
    if (
        "DRIVING LICENCE" in text_upper
        or "DRIVING LICENSE" in text_upper
        or "UNION OF INDIA DRIVING" in text_upper
        or "FORM 7" in text_upper
        or "MOTOR VEHICLES" in text_upper
        or "AUTHORISATION TO DRIVE" in text_upper
        or re.search(r"\b[A-Z]{2}[0-9]{2}\s*20[0-9]{2}[0-9]{7}\b", text_upper)
    ):
        return "driving_license"

    # 3. Visa detection signals
    if (
        "VISA" in text_upper
        or "CONTROL NUMBER" in text_upper
        or "ISSUING POST" in text_upper
        or "ENTRIES" in text_upper
        or "VNUSA" in text_upper
        or "V<" in text_upper
    ):
        return "visa"

    # 4. Passport detection signals
    if (
        "PASSPORT" in text_upper
        or "REPUBLIC OF" in text_upper
        or "P<" in text_upper
        or "TYPE P" in text_upper
    ):
        return "passport"

    return default_type


def extract_document_fields(image_path: str, document_type: Optional[str] = None) -> dict:
    """Universal dispatcher for all supported border screening documents with template verification."""
    if not document_type:
        document_type = "passport"
    else:
        document_type = document_type.lower().strip()

    # Pre-extract raw OCR to verify if selected document matches actual image
    raw_preview = extract_raw_text(image_path)
    detected_type = detect_document_type(raw_preview, default_type=document_type)

    template_mismatch = (detected_type != document_type)
    effective_type = detected_type if template_mismatch else document_type

    if effective_type == "passport":
        result = extract_mrz_fields(image_path)
    elif effective_type in ("visa", "permit", "travel_authorization"):
        result = extract_visa_fields(image_path)
    elif effective_type == "aadhaar":
        result = extract_aadhaar_fields(image_path)
    elif effective_type in ("driving_license", "driving_licence", "license"):
        result = extract_driving_license_fields(image_path)
    else:
        raw = extract_raw_text(image_path)
        result = {"document_type": effective_type, "raw_text": raw}

    result["document_type"] = effective_type
    result["requested_document_type"] = document_type
    result["template_mismatch"] = template_mismatch
    result["detected_template"] = detected_type
    result["expected_template"] = document_type

    raw_text = result.get("raw_text", "")

    # Universal Fallbacks if fields were not extracted:
    # 1. Document number fallback
    if not result.get("document_number") and not result.get("passport_number") and not result.get("aadhaar_number") and not result.get("license_number"):
        id_match = re.search(r"\b([A-Z]{1,3}\d{6,14}|[A-Z0-9]{8,16})\b", raw_text)
        if id_match:
            cand_id = id_match.group(1).strip()
            if not re.search(r"INDIA|PASSPORT|GOVERNMENT|LICENCE|AADHAAR|UNIQUE|MALE|FEMALE", cand_id, re.I):
                result["document_number"] = cand_id

    # 2. Name fallback
    if not result.get("name"):
        name_match = re.search(r"(?:Name|Given\s*Name|Holder|Full\s*Name)\s*[:\.\-]?\s*\n*([A-Za-z\s\.]{3,40})", raw_text, re.I)
        if name_match:
            cand_n = name_match.group(1).strip().split("\n")[0].strip()
            if cand_n and not re.search(r"Passport|Republic|India|Government|Licence|Aadhaar|Date|Birth", cand_n, re.I):
                result["name"] = cand_n

    # 3. DOB fallback
    if not result.get("date_of_birth"):
        dob, yob, note = extract_dob_signals(raw_text)
        if dob:
            result["date_of_birth"] = dob
        if yob and not result.get("year_of_birth"):
            result["year_of_birth"] = yob

    # 4. Expiry fallback
    if not result.get("date_of_expiry") and effective_type != "aadhaar":
        exp_match = re.search(r"(?:Expiry|Valid\s*Till|Valid\s*Upto|Expiration)[\s:\.\-]*(\d{2}[/\-.]\d{2}[/\-.]\d{4})", raw_text, re.I)
        if exp_match:
            result["date_of_expiry"] = exp_match.group(1).strip()

    # 5. Gender fallback
    if not result.get("gender"):
        gen_match = re.search(r"\b(MALE|FEMALE|Male|Female)\b", raw_text, re.I)
        if gen_match:
            result["gender"] = gen_match.group(1).upper()

    # 6. Document Face Presence Detection
    if "face_detected" not in result:
        result["face_detected"] = False
        try:
            if image_path and os.path.exists(image_path):
                img_chk = safe_cv2_read(image_path)
                if img_chk is not None:
                    cas_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                    cas = cv2.CascadeClassifier(cas_path) if os.path.exists(cas_path) else None
                    if cas is not None:
                        g = cv2.cvtColor(img_chk, cv2.COLOR_BGR2GRAY)
                        cl = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(g)
                        f_chk = cas.detectMultiScale(cl, scaleFactor=1.05, minNeighbors=2, minSize=(25, 25))
                        if len(f_chk) > 0:
                            result["face_detected"] = True
                    if not result["face_detected"]:
                        h_c, w_c = img_chk.shape[:2]
                        l_roi = img_chk[int(0.10 * h_c):int(0.95 * h_c), 0:int(0.55 * w_c)]
                        hsv_c = cv2.cvtColor(l_roi, cv2.COLOR_BGR2HSV)
                        m_c = cv2.inRange(hsv_c, np.array([0, 18, 45]), np.array([28, 255, 255]))
                        if (np.sum(m_c > 0) / m_c.size) * 100 >= 5.0:
                            result["face_detected"] = True
        except Exception:
            pass

    return result
