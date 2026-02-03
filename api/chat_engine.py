from db import supabase
from openai import OpenAI

client = OpenAI()

def chat_about_job(job_id: str, question: str) -> str:
    # 1. Fetch parsed SIP calls
    res = supabase.table("sip_calls") \
        .select("call_id,outcome,reason,root_cause,events") \
        .eq("job_id", job_id) \
        .execute()

    calls = res.data or []

    # 2. Build compact context (VERY IMPORTANT)
    summary_lines = []
    for c in calls:
        summary_lines.append(
            f"- Call-ID: {c['call_id']}, "
            f"Outcome: {c['outcome']}, "
            f"Reason: {c['reason']}"
        )

    context = (
        f"Parsed SIP Calls ({len(calls)} total):\n"
        + "\n".join(summary_lines)
    )

    # 3. Ask AI WITH CONTEXT
    prompt = f"""
You are a telecom SIP expert.

Context:
{context}

User question:
{question}

Answer ONLY using the context above.
If packet numbers are not available, say so clearly.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    return response.choices[0].message.content
