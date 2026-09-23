"""
Main FastAPI application — ties all 4 modules together into one endpoint.

Run with:
    uvicorn main:app --reload

Then open http://127.0.0.1:8000/docs to test uploads via Swagger UI
before you build the frontend.
"""

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import shutil
import os
import uuid

from module1_ocr import extract_mrz_fields
from module2_validation import run_all_validations
from module3_tampering import run_tampering_detection
from module4_face import verify_face_match
from risk_score import calculate_risk_score

app = FastAPI(title="AI-Based Fake Identity & Document Screening System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
OUTPUT_DIR = "outputs"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

app.mount("/outputs", StaticFiles(directory=OUTPUT_DIR), name="outputs")


def save_upload(file: UploadFile) -> str:
    ext = os.path.splitext(file.filename)[1]
    filename = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return path


@app.post("/screen-document")
async def screen_document(
    document_image: UploadFile = File(...),
    live_photo: UploadFile = File(None),  # optional — for face match
):
    """
    Main pipeline endpoint. Upload a document image (and optionally a live
    selfie) to run the full OCR -> validation -> tampering -> face pipeline.
    """
    doc_path = save_upload(document_image)

    # Module 1: OCR / MRZ extraction
    mrz_data = extract_mrz_fields(doc_path)

    # Module 2: Validation
    validation_result = run_all_validations(mrz_data)

    # Module 3: Tampering detection
    tampering_result = run_tampering_detection(doc_path, output_dir=OUTPUT_DIR)

    # Module 4: Face verification (only if a live photo was provided)
    face_result = {"match": True, "note": "No live photo provided — skipped"}
    if live_photo is not None:
        live_path = save_upload(live_photo)
        face_result = verify_face_match(doc_path, live_path)

    # Combine into risk score
    risk = calculate_risk_score(mrz_data, validation_result, tampering_result, face_result)

    return {
        "extracted_fields": mrz_data,
        "validation": validation_result,
        "tampering_detection": tampering_result,
        "face_verification": face_result,
        "risk_assessment": risk,
    }


@app.get("/")
def health_check():
    return {"status": "running", "message": "Fake Identity & Document Screening API"}
