"""
Module 3: AI Tampering Detection & Image Forensics
Ministry of Home Affairs / SSB AI Border Document Screening System

Implements multi-layer visual forensics:
1. Error Level Analysis (ELA) with generated difference map.
2. Paste boundary anomaly & edge discontinuity analysis.
3. EXIF metadata analysis for editing software signatures.
4. Passport printed visible DOB vs ICAO 9303 MRZ DOB cross-field alteration check.
5. Visual bounding box annotation highlighting suspicious image regions for officer inspection.
"""

import os
import re
import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from typing import Optional, Dict, Any, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

EDITING_SOFTWARE_SIGNATURES = [
    "photoshop",
    "gimp",
    "canva",
    "picsart",
    "snapseed",
    "lightroom",
    "paint.net",
    "coreldraw",
    "pixlr",
    "fotor",
]


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


def run_error_level_analysis(image_path: str, quality: int = 90) -> dict:
    """Perform Error Level Analysis (ELA) by re-compressing and measuring error."""
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    output_ela_path = os.path.join(OUTPUT_DIR, f"ela_{base_name}.jpg")

    try:
        original = Image.open(image_path).convert("RGB")
        resaved_path = os.path.join(OUTPUT_DIR, f"temp_resaved_{base_name}.jpg")
        original.save(resaved_path, "JPEG", quality=quality)
        resaved = Image.open(resaved_path)

        ela_image = ImageChops.difference(original, resaved)
        extrema = ela_image.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        scale = 255.0 / max_diff if max_diff != 0 else 1.0

        enhanced_ela = ImageEnhance.Brightness(ela_image).enhance(scale * 1.5)
        enhanced_ela.save(output_ela_path)

        if os.path.exists(resaved_path):
            os.remove(resaved_path)

        ela_arr = np.array(ela_image)
        mean_diff = float(np.mean(ela_arr))
        max_diff_val = float(np.max(ela_arr))

        is_suspicious = mean_diff > 12.0 or max_diff_val > 80.0
        return {
            "mean_error": round(mean_diff, 2),
            "max_error": round(max_diff_val, 2),
            "output_path": output_ela_path,
            "suspicious": is_suspicious,
        }
    except Exception as e:
        return {
            "mean_error": 0.0,
            "max_error": 0.0,
            "output_path": None,
            "suspicious": False,
            "error": str(e),
        }


def detect_paste_boundaries(image_path: str) -> dict:
    """Detect sharp boundary discontinuities and rectangular copy-paste regions."""
    try:
        img = safe_cv2_read(image_path)
        if img is None:
            return {"boundary_anomalies_count": 0, "suspicious": False, "boxes": []}

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)

        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        suspicious_boxes = []

        h, w = gray.shape
        min_area = (h * w) * 0.005
        max_area = (h * w) * 0.40

        for c in contours:
            area = cv2.contourArea(c)
            if min_area < area < max_area:
                x, y, bw, bh = cv2.boundingRect(c)
                aspect_ratio = float(bw) / bh if bh > 0 else 0
                if 0.5 < aspect_ratio < 4.0:
                    suspicious_boxes.append((x, y, bw, bh))

        is_suspicious = len(suspicious_boxes) >= 4
        return {
            "boundary_anomalies_count": len(suspicious_boxes),
            "suspicious": is_suspicious,
            "boxes": suspicious_boxes[:10],
        }
    except Exception as e:
        return {"boundary_anomalies_count": 0, "suspicious": False, "boxes": [], "error": str(e)}


# ---------------------------------------------------------------------------
# EXIF & Metadata Forensics Analyzer
# ---------------------------------------------------------------------------

def check_metadata_tampering(image_path: str) -> dict:
    """Deep EXIF metadata analysis: editing software, stripped tags, timestamp & compression checks."""
    try:
        from PIL.ExifTags import TAGS, GPSTAGS
        from datetime import datetime

        img = Image.open(image_path)
        exif = img.getexif()

        result = {
            "has_exif": False,
            "software_detected": [],
            "stripped_exif": False,
            "timestamp_anomaly": False,
            "timestamp_details": None,
            "datetime_original": None,
            "camera_make": None,
            "camera_model": None,
            "resolution": img.size,
            "color_mode": img.mode,
            "format": img.format,
            "suspicious": False,
            "severity": "LOW",  # CRITICAL, WARNING, INFO, LOW
            "signals": [],
            "note": "Metadata evaluated",
        }

        # Check raw image info and XMP tags for software signatures
        raw_info_str = str(img.info).lower()
        detected_software = []

        for soft in EDITING_SOFTWARE_SIGNATURES:
            if soft in raw_info_str:
                detected_software.append(f"Header/XMP: {soft.capitalize()}")

        if exif:
            result["has_exif"] = True
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                val_str = str(value)
                val_lower = val_str.lower()

                # Camera details
                if tag_name == "Make":
                    result["camera_make"] = val_str
                elif tag_name == "Model":
                    result["camera_model"] = val_str
                elif tag_name in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                    result["datetime_original"] = val_str

                # Software tag check
                if tag_name == "Software":
                    for soft in EDITING_SOFTWARE_SIGNATURES:
                        if soft in val_lower:
                            detected_software.append(f"Software Tag: {val_str}")

                # General tag value check
                for soft in EDITING_SOFTWARE_SIGNATURES:
                    if soft in val_lower and f"Software Tag: {val_str}" not in detected_software:
                        detected_software.append(f"{tag_name}: {val_str}")

            # Timestamp Consistency Check
            if result.get("datetime_original"):
                try:
                    # Standard EXIF format: 'YYYY:MM:DD HH:MM:SS'
                    dto_str = result["datetime_original"]
                    dto_dt = datetime.strptime(dto_str[:19], "%Y:%m:%d %H:%M:%S")
                    now = datetime.now()
                    if dto_dt > now:
                        result["timestamp_anomaly"] = True
                        result["timestamp_details"] = f"Future timestamp detected in EXIF: {dto_str}"
                except Exception:
                    pass

        else:
            # Missing / Stripped EXIF
            if img.format in ("JPEG", "JPG", "TIFF"):
                result["stripped_exif"] = True
                result["signals"].append({
                    "name": "EXIF Data Sanitization",
                    "level": "INFO",
                    "message": "EXIF metadata stripped/absent (typical for web downloads, messaging apps, or sanitized scans)",
                })

        # Assess Severity and Flags
        if detected_software:
            result["software_detected"] = list(set(detected_software))
            result["suspicious"] = True
            result["severity"] = "CRITICAL"
            result["note"] = f"Image editing software signatures detected: {', '.join(result['software_detected'])}"
            result["signals"].append({
                "name": "Editing Software Signature",
                "level": "CRITICAL",
                "message": f"Document processed by image editor: {', '.join(result['software_detected'])}",
            })
        elif result.get("timestamp_anomaly"):
            result["suspicious"] = True
            result["severity"] = "WARNING"
            result["note"] = result["timestamp_details"]
            result["signals"].append({
                "name": "Timestamp Inconsistency",
                "level": "WARNING",
                "message": result["timestamp_details"],
            })
        elif result.get("has_exif"):
            result["severity"] = "LOW"
            camera_str = f" ({result['camera_make']} {result['camera_model']})" if result.get("camera_make") else ""
            result["note"] = f"Original EXIF metadata intact{camera_str}"
            result["signals"].append({
                "name": "EXIF Integrity",
                "level": "LOW",
                "message": f"Original capture metadata present{camera_str}",
            })
        else:
            result["severity"] = "LOW"
            result["note"] = "Standard digital image structure (no editing software traces)"

        return result

    except Exception as e:
        return {
            "has_exif": False,
            "software_detected": [],
            "stripped_exif": True,
            "timestamp_anomaly": False,
            "suspicious": False,
            "severity": "LOW",
            "signals": [],
            "note": f"Metadata evaluated: {str(e)}",
            "error": str(e),
        }


def check_passport_dob_alteration(extracted_fields: dict, raw_ocr_text: Optional[str] = None, doc_type: str = "passport") -> dict:
    """Compare visible printed DOB against ICAO 9303 MRZ DOB for visible-field alteration (Passport only)."""
    effective_doc_type = (doc_type or extracted_fields.get("document_type") or "").lower()
    if effective_doc_type != "passport":
        return {"detected": False, "reason": None}

    if not extracted_fields:
        return {"detected": False, "reason": None}

    mrz_fields = extracted_fields.get("mrz_fields", {})
    mrz_dob = mrz_fields.get("date_of_birth") or extracted_fields.get("date_of_birth")
    if not mrz_dob:
        return {"detected": False, "reason": None}

    mrz_dob_norm = mrz_dob.replace("/", "-").replace(".", "-").strip()

    # Known non-DOB dates on document to ignore
    issue_date = str(extracted_fields.get("date_of_issue") or extracted_fields.get("visual_fields", {}).get("date_of_issue") or "").replace("/", "-").replace(".", "-").strip()
    expiry_date = str(extracted_fields.get("date_of_expiry") or extracted_fields.get("visual_fields", {}).get("date_of_expiry") or "").replace("/", "-").replace(".", "-").strip()

    # 1. Check if visual DOB is already explicitly extracted
    vis_fields = extracted_fields.get("visual_fields", {})
    vis_dob = vis_fields.get("date_of_birth")
    if vis_dob:
        vis_dob_norm = str(vis_dob).replace("/", "-").replace(".", "-").strip()
        # If visual DOB matches MRZ DOB, perfectly clean
        if vis_dob_norm == mrz_dob_norm:
            return {"detected": False, "reason": None}
        # If visual DOB was mistakenly assigned issue date or expiry date, it's an OCR field misattribution, not tampering
        if (issue_date and vis_dob_norm == issue_date) or (expiry_date and vis_dob_norm == expiry_date):
            return {"detected": False, "reason": None}
        # Otherwise genuine mismatch between printed DOB and MRZ DOB
        return {
            "detected": True,
            "visible_dob": vis_dob_norm,
            "mrz_dob": mrz_dob_norm,
            "reason": (
                f"CRITICAL CROSS-FIELD MISMATCH: Printed DOB ({vis_dob_norm}) does not match "
                f"MRZ DOB ({mrz_dob_norm}). Possible visible-field alteration."
            ),
        }

    # 2. Check raw OCR text ONLY if explicitly labeled with DOB keyword
    raw = raw_ocr_text or extracted_fields.get("raw_text", "")
    if not raw:
        return {"detected": False, "reason": None}

    dob_label_regex = re.compile(
        r"(?:DOB|Date\s*of\s*Birth|Birth\s*Date|D\.O\.B|जन्म\s*तिथि)[\s:\.\-]*\n?[\s:\.\-]*(\d{2}[/\-.]\d{2}[/\-.]\d{4})",
        re.IGNORECASE,
    )
    m = dob_label_regex.search(raw)
    if m:
        cand = m.group(1).replace("/", "-").replace(".", "-").strip()
        if cand != mrz_dob_norm and cand != issue_date and cand != expiry_date:
            return {
                "detected": True,
                "visible_dob": cand,
                "mrz_dob": mrz_dob_norm,
                "reason": (
                    f"CRITICAL CROSS-FIELD MISMATCH: Printed DOB ({cand}) does not match "
                    f"MRZ DOB ({mrz_dob_norm}). Possible visible-field alteration."
                ),
            }

    return {"detected": False, "reason": None}


def generate_annotated_forensic_image(
    image_path: str,
    suspicious_boxes: List[Any],
    has_dob_mismatch: bool = False,
) -> Optional[str]:
    """
    Generate an annotated image with colored bounding boxes around suspicious regions
    for the officer investigation view.
    """
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    output_annotated_path = os.path.join(OUTPUT_DIR, f"annotated_{base_name}.jpg")

    try:
        img = safe_cv2_read(image_path)
        if img is None:
            return None

        h, w, _ = img.shape

        # 1. Highlight suspicious boundary regions (Orange)
        for (x, y, bw, bh) in suspicious_boxes:
            cv2.rectangle(img, (x, y), (x + bw, y + bh), (0, 140, 255), 2)
            cv2.putText(img, "ANOMALY", (x, max(15, y - 5)), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 140, 255), 1)

        # 2. If DOB alteration detected, highlight the central text region in RED
        if has_dob_mismatch:
            tx = int(w * 0.25)
            ty = int(h * 0.35)
            tw = int(w * 0.45)
            th = int(h * 0.25)
            cv2.rectangle(img, (tx, ty), (tx + tw, ty + th), (0, 0, 255), 3)
            cv2.putText(img, "ALTERATION: DOB MISMATCH", (tx, max(20, ty - 8)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)

        # 3. Add Forensic Watermark
        cv2.putText(img, "SSB AI FORENSIC ANNOTATION - INSPECTION VIEW", (10, h - 12), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)

        cv2.imwrite(output_annotated_path, img)
        return output_annotated_path
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Master Tampering Analysis Pipeline
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Section 1.3: Stamp & Seal Detection & Forensics
# ---------------------------------------------------------------------------

def detect_stamps_and_seals(image_path: str, doc_type: str = "passport") -> dict:
    """
    Detect official consular stamps, border control ink seals, and revenue stamps.
    Uses:
    1. HSV color segmentation for official ink formulations (Red/Magenta, Blue/Purple, Green).
    2. Circular and elliptical contour fitting + cv2.HoughCircles.
    3. Position and overlap analysis (flagging unnatural MRZ or photo face overlap).
    4. Ink color consistency checks.
    """
    result = {
        "stamp_count": 0,
        "stamps": [],
        "dominant_color": "NONE",
        "color_consistency": "CONSISTENT",
        "suspicious": False,
        "anomalies": [],
        "signals": [],
        "annotated_stamp_boxes": [],
    }

    try:
        img = safe_cv2_read(image_path)
        if img is None:
            return result

        h, w, _ = img.shape
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

        # Color masks for stamp inks
        mask_r1 = cv2.inRange(hsv, np.array([0, 50, 50]), np.array([12, 255, 255]))
        mask_r2 = cv2.inRange(hsv, np.array([165, 50, 50]), np.array([180, 255, 255]))
        mask_red = cv2.bitwise_or(mask_r1, mask_r2)

        mask_blue = cv2.inRange(hsv, np.array([95, 45, 45]), np.array([145, 255, 255]))
        mask_purple = cv2.inRange(hsv, np.array([140, 40, 40]), np.array([165, 255, 255]))

        stamp_mask = cv2.bitwise_or(cv2.bitwise_or(mask_red, mask_blue), mask_purple)

        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
        closed_mask = cv2.morphologyEx(stamp_mask, cv2.MORPH_CLOSE, kernel, iterations=2)

        contours, _ = cv2.findContours(closed_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        min_stamp_area = (h * w) * 0.0015
        max_stamp_area = (h * w) * 0.25

        detected_stamps = []
        ink_colors = []

        for c in contours:
            area = cv2.contourArea(c)
            if min_stamp_area < area < max_stamp_area:
                perimeter = cv2.arcLength(c, True)
                if perimeter > 0:
                    circularity = 4 * np.pi * (area / (perimeter * perimeter))
                else:
                    circularity = 0

                x, y, bw, bh = cv2.boundingRect(c)
                aspect_ratio = float(bw) / bh if bh > 0 else 0

                if (0.35 <= circularity <= 1.2 and 0.55 <= aspect_ratio <= 1.8) or area > (min_stamp_area * 2):
                    roi_hsv = hsv[y:y+bh, x:x+bw]
                    red_cnt = np.sum((roi_hsv[:, :, 0] < 12) | (roi_hsv[:, :, 0] > 165))
                    blue_cnt = np.sum((roi_hsv[:, :, 0] >= 95) & (roi_hsv[:, :, 0] <= 145))
                    purple_cnt = np.sum((roi_hsv[:, :, 0] > 140) & (roi_hsv[:, :, 0] <= 165))

                    if red_cnt >= blue_cnt and red_cnt >= purple_cnt:
                        color = "RED/MAGENTA"
                    elif purple_cnt >= blue_cnt:
                        color = "PURPLE"
                    elif blue_cnt > 0:
                        color = "BLUE"
                    else:
                        color = "DARK_INK"

                    ink_colors.append(color)

                    overlaps_mrz = (y + bh) > (h * 0.78) and doc_type.lower() == "passport"
                    overlaps_photo_core = (x < w * 0.45) and (y < h * 0.65) and (y > h * 0.15) and (x > w * 0.05)

                    detected_stamps.append({
                        "box": [int(x), int(y), int(bw), int(bh)],
                        "center": [int(x + bw / 2), int(y + bh / 2)],
                        "area": int(area),
                        "circularity": round(float(circularity), 2),
                        "color": color,
                        "overlaps_mrz": overlaps_mrz,
                        "overlaps_photo_core": overlaps_photo_core,
                    })

        result["stamp_count"] = len(detected_stamps)
        result["stamps"] = detected_stamps
        result["annotated_stamp_boxes"] = [s["box"] for s in detected_stamps]

        if ink_colors:
            from collections import Counter
            counts = Counter(ink_colors)
            result["dominant_color"] = counts.most_common(1)[0][0]
            if len(set(ink_colors)) > 2:
                result["color_consistency"] = "MIXED_INKS"
                result["anomalies"].append("Multiple conflicting stamp ink formulations detected")
        else:
            result["dominant_color"] = "NONE"

        for st in detected_stamps:
            if st["overlaps_mrz"]:
                result["suspicious"] = True
                msg = "Stamp unnaturally overlaps ICAO MRZ machine-readable area (potential MRZ tampering)"
                if msg not in result["anomalies"]:
                    result["anomalies"].append(msg)
            if st["overlaps_photo_core"] and st["circularity"] > 0.8:
                msg = "Circular official seal positioned over primary facial photograph zone"
                if msg not in result["anomalies"]:
                    result["anomalies"].append(msg)

        if doc_type.lower() in ("visa", "permit") and len(detected_stamps) == 0:
            result["anomalies"].append("Missing expected consular / border entry stamp on visa document")

        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def analyze_tampering(
    image_path: str,
    doc_type: str = "passport",
    extracted_fields: Optional[dict] = None,
) -> dict:
    ela_res = run_error_level_analysis(image_path)
    boundary_res = detect_paste_boundaries(image_path)
    meta_res = check_metadata_tampering(image_path)
    stamp_res = detect_stamps_and_seals(image_path, doc_type=doc_type)
    dob_mrz_res = check_passport_dob_alteration(
        extracted_fields or {},
        extracted_fields.get("raw_text") if extracted_fields else None,
        doc_type=doc_type,
    )

    tampering_score = 0
    signals: List[Dict[str, Any]] = []

    # 1. ELA Signal (0-25 pts)
    if ela_res.get("suspicious"):
        tampering_score += 25
        signals.append({
            "name": "Error Level Analysis (ELA)",
            "level": "HIGH",
            "message": f"Inconsistent compression noise detected (Mean Error: {ela_res['mean_error']})",
        })
    else:
        signals.append({
            "name": "Error Level Analysis (ELA)",
            "level": "LOW",
            "message": f"Uniform compression structure (Mean Error: {ela_res['mean_error']})",
        })

    # 2. Boundary / Paste Anomalies (0-25 pts)
    if boundary_res.get("suspicious"):
        tampering_score += 25
        signals.append({
            "name": "Paste Boundary Detection",
            "level": "MEDIUM",
            "message": f"{boundary_res['boundary_anomalies_count']} suspicious boundary discontinuities found",
        })
    else:
        signals.append({
            "name": "Paste Boundary Detection",
            "level": "LOW",
            "message": "No anomalous rectangular splice boundaries detected",
        })

    # 3. Metadata & EXIF Forensics (0-20 pts)
    meta_sev = meta_res.get("severity", "LOW")
    if meta_sev == "CRITICAL":
        tampering_score += 20
        signals.append({
            "name": "EXIF Metadata Forensics",
            "level": "CRITICAL",
            "message": f"Image editing software signatures detected: {', '.join(meta_res.get('software_detected', []))}",
        })
    elif meta_sev == "WARNING":
        tampering_score += 10
        signals.append({
            "name": "EXIF Metadata Forensics",
            "level": "WARNING",
            "message": meta_res.get("note", "Metadata timestamp anomaly detected"),
        })
    else:
        signals.append({
            "name": "EXIF Metadata Forensics",
            "level": "LOW",
            "message": meta_res.get("note", "Standard image metadata structure (clean)"),
        })

    # 4. Cross-Field DOB Alteration (Passport Only, 0-30 pts)
    if doc_type.lower() == "passport":
        if dob_mrz_res.get("detected"):
            tampering_score += 30
            signals.append({
                "name": "MRZ vs Printed Cross-Check",
                "level": "CRITICAL",
                "message": dob_mrz_res["reason"],
            })
        else:
            signals.append({
                "name": "MRZ vs Printed Cross-Check",
                "level": "LOW",
                "message": "Printed visible DOB matches ICAO 9303 MRZ encoded date of birth",
            })

    # 5. Stamp & Seal Forensics (0-20 pts)
    if stamp_res.get("suspicious"):
        tampering_score += 20
        for anom in stamp_res.get("anomalies", []):
            signals.append({
                "name": "Stamp & Seal Forensics",
                "level": "HIGH",
                "message": anom,
            })
    elif stamp_res.get("stamp_count", 0) > 0:
        signals.append({
            "name": "Stamp & Seal Forensics",
            "level": "LOW",
            "message": f"{stamp_res['stamp_count']} official stamp(s) verified (Ink: {stamp_res['dominant_color']})",
        })
    elif doc_type.lower() in ("visa", "permit"):
        tampering_score += 15
        signals.append({
            "name": "Stamp & Seal Forensics",
            "level": "MEDIUM",
            "message": "Missing official consular seal on visa credential",
        })

    tampering_score = min(tampering_score, 100)

    if tampering_score >= 60:
        overall_flag = "HIGH"
    elif tampering_score >= 25:
        overall_flag = "MEDIUM"
    else:
        overall_flag = "LOW"

    # Generate annotated image
    annotated_path = generate_annotated_forensic_image(
        image_path,
        boundary_res.get("boxes", []),
        has_dob_mismatch=dob_mrz_res.get("detected", False),
    )

    return {
        "tampering_score": tampering_score,
        "tampering_percentage": f"{tampering_score}%",
        "overall_flag": overall_flag,
        "signals": signals,
        "ela": ela_res,
        "boundary": boundary_res,
        "metadata": meta_res,
        "dob_mrz_check": dob_mrz_res,
        "stamps": stamp_res,
        "annotated_image_path": annotated_path,
    }