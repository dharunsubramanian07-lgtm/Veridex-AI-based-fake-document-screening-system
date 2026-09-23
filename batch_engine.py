"""
Batch Screening Engine & Throughput Analytics
VERIDEX — AI Identity & Document Screening System
Ministry of Home Affairs / SSB — Blockchain & Cybersecurity Theme

Features:
- High-throughput multi-document screening pipeline.
- ZIP archive unpacking with zipbomb protection and secure staging.
- Real-time progress updates with document-level status callbacks.
- Computes throughput metrics: Docs/Minute, Avg Sec/Doc, Risk Distribution.
- Generates downloadable CSV summary and combined JSON audit report.
"""

import os
import io
import time
import zipfile
import csv
import json
import tempfile
import uuid
from typing import List, Dict, Any, Optional, Callable, Tuple

from security_validator import validate_file_upload, sanitize_filename
from module5_risk import screen_document
from module6_blockchain import global_ledger


def process_batch(
    uploaded_files: List[Any],
    default_doc_type: str = "passport",
    officer_id: str = "SSB-BATCH-OFFICER",
    checkpoint_id: str = "SSB-ICP-RAXAUL",
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Dict[str, Any]:
    """
    Process a collection of uploaded files or a ZIP archive through the 6-layer screening pipeline.
    """
    start_time = time.time()
    temp_dir = tempfile.mkdtemp(prefix="veridex_batch_")
    extracted_file_paths: List[Tuple[str, str]] = []  # (filepath, original_name)

    # 1. Unpack & Stage Files
    try:
        for f in uploaded_files:
            fname = getattr(f, "name", "document.jpg")
            fbytes = f.read() if hasattr(f, "read") else bytes(f)

            if fname.lower().endswith(".zip"):
                # Handle ZIP archive safely
                try:
                    with zipfile.ZipFile(io.BytesIO(fbytes), "r") as zf:
                        # Zipbomb check: limit total uncompressed size to 50 MB and max 100 files
                        total_uncompressed = sum(zi.file_size for zi in zf.infolist())
                        if total_uncompressed > 50 * 1024 * 1024 or len(zf.infolist()) > 100:
                            continue
                        for member in zf.namelist():
                            if member.lower().endswith((".jpg", ".jpeg", ".png", ".pdf")) and not member.startswith("__MACOSX"):
                                member_bytes = zf.read(member)
                                clean_member_name = sanitize_filename(os.path.basename(member))
                                is_v, _, _ = validate_file_upload(member_bytes, clean_member_name)
                                if is_v:
                                    out_p = os.path.join(temp_dir, f"{uuid.uuid4().hex[:6]}_{clean_member_name}")
                                    with open(out_p, "wb") as out_f:
                                        out_f.write(member_bytes)
                                    extracted_file_paths.append((out_p, clean_member_name))
                except Exception as e:
                    print(f"[batch_engine] ZIP extraction warning: {e}")
            else:
                clean_name = sanitize_filename(fname)
                is_v, _, _ = validate_file_upload(fbytes, clean_name)
                if is_v:
                    out_p = os.path.join(temp_dir, f"{uuid.uuid4().hex[:6]}_{clean_name}")
                    with open(out_p, "wb") as out_f:
                        out_f.write(fbytes)
                    extracted_file_paths.append((out_p, clean_name))

        total_docs = len(extracted_file_paths)
        if total_docs == 0:
            return {
                "success": False,
                "total_documents": 0,
                "results": [],
                "throughput_dpm": 0.0,
                "avg_sec_per_doc": 0.0,
                "total_duration_sec": 0.0,
                "csv_data": "",
                "json_data": "[]",
                "summary": "No valid image files detected in upload batch.",
            }

        results: List[Dict[str, Any]] = []
        low_risk_cnt = 0
        med_risk_cnt = 0
        high_risk_cnt = 0

        # 2. Run Pipeline on Each Document
        for idx, (doc_path, orig_name) in enumerate(extracted_file_paths):
            doc_start = time.time()
            if progress_callback:
                progress_callback(idx + 1, total_docs, f"Screening [{idx+1}/{total_docs}]: {orig_name}")

            screening_id = f"SCR-BATCH-{int(time.time())}-{idx+1:03d}"
            try:
                screen_res = screen_document(
                    document_path=doc_path,
                    document_type=default_doc_type,
                    screening_id=screening_id,
                )

                risk_info = screen_res["risk"]
                fields_info = screen_res["fields"]
                val_info = screen_res["validation"]
                doc_dur = time.time() - doc_start

                # Commit to blockchain ledger
                rec_block = global_ledger.add_screening_record(
                    screening_id=screening_id,
                    officer_id=officer_id,
                    checkpoint_id=checkpoint_id,
                    document_type=screen_res["document_type"],
                    document_number=fields_info.get("document_number"),
                    document_filepath=doc_path,
                    risk_score=risk_info["risk_score"],
                    ai_recommendation=risk_info["recommended_action"],
                    officer_decision=risk_info["recommended_action"],
                )

                score = risk_info["risk_score"]
                level = risk_info["risk_level"]
                if score < 50:
                    low_risk_cnt += 1
                elif score < 70:
                    med_risk_cnt += 1
                else:
                    high_risk_cnt += 1

                # Compile flags summary
                flags = []
                for b in risk_info.get("breakdown", []):
                    if b["points"] > 0:
                        flags.append(f"{b['factor']} (+{b['points']}p)")

                results.append({
                    "screening_id": screening_id,
                    "filename": orig_name,
                    "document_type": screen_res["document_type"].upper(),
                    "holder_name": fields_info.get("name") or "UNRESOLVED",
                    "doc_number_masked": rec_block["masked_doc_num"],
                    "risk_score": score,
                    "trust_index": risk_info["trust_index"],
                    "risk_level": level,
                    "recommended_action": risk_info["recommended_action"],
                    "flags": flags,
                    "flags_summary": "; ".join(flags) if flags else "CLEAR (No Anomalies)",
                    "processing_time_sec": round(doc_dur, 2),
                    "block_index": rec_block["index"],
                    "block_hash": rec_block["block_hash"],
                    "ed25519_signed": bool(rec_block.get("ed25519_signature")),
                })

            except Exception as e:
                doc_dur = time.time() - doc_start
                results.append({
                    "screening_id": screening_id,
                    "filename": orig_name,
                    "document_type": default_doc_type.upper(),
                    "holder_name": "ERROR",
                    "doc_number_masked": "N/A",
                    "risk_score": 75,
                    "trust_index": 25,
                    "risk_level": "HIGH",
                    "recommended_action": "SECONDARY INSPECTION",
                    "flags": ["PIPELINE_PROCESSING_ERROR"],
                    "flags_summary": f"Processing Warning: {str(e)}",
                    "processing_time_sec": round(doc_dur, 2),
                    "block_index": -1,
                    "block_hash": "ERROR",
                    "ed25519_signed": False,
                })
                high_risk_cnt += 1

        total_duration = time.time() - start_time
        avg_sec = round(total_duration / float(total_docs), 2)
        dpm = round((total_docs / (total_duration + 1e-6)) * 60.0, 1)

        # 3. Generate CSV
        csv_output = io.StringIO()
        fieldnames = [
            "Screening ID", "Filename", "Doc Type", "Holder Name", "Masked ID",
            "Risk Score", "Risk Level", "Recommended Action", "Flags", "Block Index", "Processing Sec"
        ]
        writer = csv.DictWriter(csv_output, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Screening ID": r["screening_id"],
                "Filename": r["filename"],
                "Doc Type": r["document_type"],
                "Holder Name": r["holder_name"],
                "Masked ID": r["doc_number_masked"],
                "Risk Score": r["risk_score"],
                "Risk Level": r["risk_level"],
                "Recommended Action": r["recommended_action"],
                "Flags": r["flags_summary"],
                "Block Index": r["block_index"],
                "Processing Sec": r["processing_time_sec"],
            })

        # 4. Generate JSON
        json_str = json.dumps({
            "batch_metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "officer_id": officer_id,
                "checkpoint_id": checkpoint_id,
                "total_documents": total_docs,
                "total_duration_sec": round(total_duration, 2),
                "throughput_docs_per_min": dpm,
                "avg_sec_per_doc": avg_sec,
                "risk_distribution": {
                    "low_risk": low_risk_cnt,
                    "medium_risk": med_risk_cnt,
                    "high_risk": high_risk_cnt,
                }
            },
            "results": results
        }, indent=2)

        return {
            "success": True,
            "total_documents": total_docs,
            "results": results,
            "low_risk_count": low_risk_cnt,
            "medium_risk_count": med_risk_cnt,
            "high_risk_count": high_risk_cnt,
            "throughput_dpm": dpm,
            "avg_sec_per_doc": avg_sec,
            "total_duration_sec": round(total_duration, 2),
            "csv_data": csv_output.getvalue(),
            "json_data": json_str,
            "summary": f"Screened {total_docs} credentials in {total_duration:.1f}s ({dpm} docs/min).",
        }

    finally:
        # Cleanup temporary files
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
