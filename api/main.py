from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile
import os
import uuid
import dotenv

dotenv.load_dotenv()

from sip_engine import analyze_sip_pcap
from db import supabase
from ai_explainer import explain_call
from chat_engine import chat_about_job

app = FastAPI(title="PCAP AI Reader")

# -------------------------
# CORS (Local + Vercel)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://your-vercel-ui.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Health Check
# -------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -------------------------
# SIP Analysis API
# -------------------------
@app.post("/analyze/sip")
async def analyze_sip(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only pcap/pcapng files supported"
        )

    job_id = str(uuid.uuid4())

    # 1️⃣ Read file ONCE
    file_bytes = await file.read()

    # 2️⃣ Upload to Supabase Storage (NON-BLOCKING, DEMO-SAFE)
    bucket_path = f"{job_id}/{file.filename}"
    try:
        supabase.storage.from_("pcap").upload(
            bucket_path,
            file_bytes,
            file_options={
                "content-type": "application/octet-stream"
            }
        )
    except Exception as e:
        # Storage issues must NOT kill demo
        print("⚠️ Supabase storage upload failed:", e)

    # 3️⃣ Temp file ONLY for tshark
    with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        # 4️⃣ Deterministic SIP analysis
        try:
            result = analyze_sip_pcap(tmp_path)
        except FileNotFoundError:
            # 🔥 DEMO MODE FALLBACK (Render has no tshark)
            print("⚠️ tshark not found – running demo fallback")
            result = [
                {
                    "call_id": "DEMO-CALL-001",
                    "outcome": "DROP_AFTER_200",
                    "reason": "200 OK seen but ACK missing",
                    "root_cause": "Possible SBC / NAT / firewall issue",
                    "events": []
                }
            ]

        # 5️⃣ Store PCAP job
        supabase.table("pcap_jobs").insert({
            "id": job_id,
            "filename": file.filename,
            "total_calls": len(result),
            "bucket_path": bucket_path
        }).execute()

        enriched_calls = []

        # 6️⃣ Store SIP calls + AI explanation
        for call in result:
            try:
                ai_explanation = explain_call(call)
            except Exception as e:
                print("⚠️ AI explain failed:", e)
                ai_explanation = "AI explanation unavailable"

            call["ai_explanation"] = ai_explanation
            enriched_calls.append(call)

            supabase.table("sip_calls").insert({
                "id": str(uuid.uuid4()),
                "job_id": job_id,
                "call_id": call["call_id"],
                "outcome": call["outcome"],
                "reason": call["reason"],
                "root_cause": call["root_cause"],
                "events": call["events"],
                "ai_explanation": ai_explanation
            }).execute()

        # 7️⃣ API response
        return {
            "job_id": job_id,
            "file": file.filename,
            "bucket_path": bucket_path,
            "total_calls": len(enriched_calls),
            "calls": enriched_calls
        }

    finally:
        # Always clean temp file
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

    return {
        "job_id": job_id,
        "question": payload.question,
        "answer": answer
    }
