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

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://your-vercel-ui.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze/sip")
async def analyze_sip(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "Only pcap/pcapng files supported")

    job_id = str(uuid.uuid4())
    file_bytes = await file.read()

    # ✅ 1. Create temp file FIRST
    with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    bucket_path = f"{job_id}/{file.filename}"

    try:
        # ✅ 2. Upload to Supabase using temp file
        with open(tmp_path, "rb") as f:
            supabase.storage().from_("pcap").upload(
                bucket_path,
                f,
                file_options={"content-type": "application/octet-stream"}
            )

        # ✅ 3. Run tshark analysis
        result = analyze_sip_pcap(tmp_path)

        # ✅ 4. Store job
        supabase.table("pcap_jobs").insert({
            "id": job_id,
            "filename": file.filename,
            "total_calls": len(result),
            "bucket_path": bucket_path
        }).execute()

        enriched_calls = []

        # ✅ 5. Store calls + AI
        for call in result:
            try:
                ai_explanation = explain_call(call)
            except Exception:
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

        return {
            "job_id": job_id,
            "file": file.filename,
            "bucket_path": bucket_path,
            "total_calls": len(enriched_calls),
            "calls": enriched_calls
        }

    finally:
        os.remove(tmp_path)

class ChatRequest(BaseModel):
    question: str

@app.post("/chat/{job_id}")
async def chat(job_id: str, payload: ChatRequest):
    answer = chat_about_job(job_id, payload.question)
    return {
        "job_id": job_id,
        "question": payload.question,
        "answer": answer
    }
