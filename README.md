# AI-Based Fake Identity & Document Screening System — Prototype

## Setup (run these once)

```bash
# 1. Create and activate virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 2. Install Tesseract OCR (system-level, not pip)
# Windows: https://github.com/UB-Mannheim/tesseract/wiki (add to PATH)
# Mac: brew install tesseract
# Linux: sudo apt install tesseract-ocr

# 3. Install Python packages
pip install -r requirements.txt
```

## Run the backend

```bash
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/docs — this gives you a free test UI (Swagger)
to upload images and see results before building any frontend.

## Folder structure

- `module1_ocr.py` — OCR + MRZ extraction
- `module2_validation.py` — rule-based document validation
- `module3_tampering.py` — Error Level Analysis + metadata tampering detection
- `module4_face.py` — face match between document photo and live photo
- `risk_score.py` — combines all module outputs into a single risk score
- `main.py` — FastAPI app wiring everything together
- `sample_docs/` — put your test images here
- `uploads/` — uploaded images get saved here at runtime
- `outputs/` — generated ELA heatmap images saved here

## Testing

1. Put a passport image with a visible MRZ into `sample_docs/`
2. Test each module individually first:
   ```bash
   python module1_ocr.py
   python module3_tampering.py
   ```
3. Then run the full API and test via `/docs` Swagger UI by uploading a file
