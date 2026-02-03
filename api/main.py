from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile
import os
import uuid
import dotenv

dotenv.load_dotenv()

from call_analyzer import analyze_pcap_calls
from db import supabase
from ai_explainer import explain_call
from chat_engine import chat_about_job
from tshark_runner import get_packet_counts, analyze_capture_context

# -------------------------
# CONFIG
# -------------------------
ENABLE_SUPABASE = True  # set False to fully disable DB during demo

app = FastAPI(title="PCAP AI Reader")

# -------------------------
# CORS
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Helpers
# -------------------------
def safe_supabase_insert(table: str, payload: dict):
    if not ENABLE_SUPABASE:
        return
    try:
        supabase.table(table).insert(payload).execute()
    except Exception as e:
        print(f"⚠️ Supabase insert failed [{table}]: {e}")

def safe_supabase_storage_upload(bucket: str, path: str, file_bytes: bytes):
    if not ENABLE_SUPABASE:
        return
    try:
        supabase.storage.from_(bucket).upload(
            path,
            file_bytes,
            file_options={"content-type": "application/octet-stream"},
        )
    except Exception as e:
        print("⚠️ Storage upload failed:", e)

# -------------------------
# Health Check
# -------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -------------------------
# SIP Analysis API (MVP-1)
# -------------------------
@app.post("/analyze/sip")
async def analyze_sip(file: UploadFile = File(...)):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file received")

    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail=f"Only pcap/pcapng supported: {file.filename}")

    job_id = str(uuid.uuid4())

    # 1) Read bytes once
    file_bytes = await file.read()

    # 2) Upload original PCAP to storage (best effort)
    bucket_path = f"{job_id}/{file.filename}"
    safe_supabase_storage_upload("pcap", bucket_path, file_bytes)

    # 3) Write temp file for tshark
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        # 4) Deterministic analysis (engine)
        analysis = analyze_pcap_calls(tmp_path)

        # 5) File-level facts (what PCAP is about)
        packet_stats = get_packet_counts(tmp_path)
        context_info = analyze_capture_context(tmp_path)  # includes protocol hierarchy + capture context

        # 6) File-level AI Insight (so UI can show it immediately)
        # We reuse explain_call() by passing a "file summary" object.
        file_ai_input = {
            "type": "FILE_SUMMARY",
            "filename": file.filename,
            "packet_stats": packet_stats,
            "context": context_info.get("context"),
            "total_calls": analysis.get("total_calls"),
            "calls_preview": analysis.get("calls", [])[:5],  # keep it small for cost + speed
        }
        file_ai_insight = explain_call(file_ai_input, "Give file overview + key issues + what to check in Wireshark next.")

        # 7) Save pcap job
        safe_supabase_insert("pcap_jobs", {
            "id": job_id,
            "filename": file.filename,
            "total_calls": analysis.get("total_calls", 0),
            "bucket_path": bucket_path
        })

        # 8) Save each call row + per-call AI explanation (optional but good)
        for call in analysis.get("calls", []):
            try:
                ai_text = explain_call(call, "Explain this call in bullet points for an engineer.")
            except Exception as e:
                print("⚠️ AI explanation failed:", e)
                ai_text = "AI explanation unavailable"

            safe_supabase_insert("sip_calls", {
                "id": str(uuid.uuid4()),
                "job_id": job_id,
                "call_id": call.get("call_id"),

                # schema-aligned
                "outcome": call.get("final_verdict"),
                "reason": call.get("root_cause"),
                "root_cause": call.get("root_cause"),
                "events": call.get("timeline"),

                "ai_explanation": ai_text
            })

        # 9) Response (UI should display these)
        return {
            "job_id": job_id,
            "file": file.filename,
            "bucket_path": bucket_path,

            # NEW: file overview
            "packet_stats": packet_stats,
            "capture_context": context_info.get("context"),
            "total_calls": analysis.get("total_calls", 0),

            # NEW: AI insight for the entire file
            "file_ai_insight": file_ai_insight,

            # keep calls so UI can show “all details”
            "calls": analysis.get("calls", [])
        }

    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

# -------------------------
# Chat API
# -------------------------
class ChatRequest(BaseModel):
    question: str

@app.post("/chat/{job_id}")
async def chat(job_id: str, payload: ChatRequest):
    if not payload.question:
        raise HTTPException(400, "Question is required")

    answer = chat_about_job(job_id, payload.question)

    return {"job_id": job_id, "question": payload.question, "answer": answer}
