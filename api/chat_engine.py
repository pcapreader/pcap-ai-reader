import os
from openai import OpenAI
from db import supabase

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a senior telecom core network engineer.
You answer questions strictly using the provided SIP analysis data.
Do not invent facts.
If data is insufficient, say so.
"""

def chat_about_job(job_id: str, question: str) -> str:
    resp = supabase.table("sip_calls") \
        .select("call_id, outcome, root_cause, ai_explanation") \
        .eq("job_id", job_id) \
        .execute()

    calls = resp.data or []

    if not calls:
        return "No SIP analysis data found for this job."

    context = "SIP Analysis Summary:\n"

    for c in calls:
        context += f"""
Call-ID: {c['call_id']}
Outcome: {c['outcome']}
Root Cause: {c['root_cause']}
AI Summary: {c['ai_explanation']}
"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": context},
        {"role": "user", "content": f"Question: {question}"}
    ]

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2
    )

    return response.choices[0].message.content
