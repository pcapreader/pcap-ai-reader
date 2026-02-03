import os
import json
from typing import Optional
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a Senior telecom troubleshooting engineer.

STRICT RULES:
- You do NOT analyze packets.
- You do NOT guess or speculate.
- You ONLY explain the provided analysis JSON.
- You MUST NOT contradict the engine verdict.
- If a value is null, explain why it is null.
- Reference packet numbers when available.
- If data is missing, say it is not present in the capture.
"""


def explain_call(call_context: dict, question: Optional[str] = None) -> str:
    """
    MVP-1 AI explainer.
    Explains engine-produced analysis ONLY.
    """

    payload = {
        "analysis": call_context,
        "question": question or "Explain the call failure clearly."
    }

    try:
        response = client.chat.completions.create(
             model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(payload, indent=2)
                }
            ],
            temperature=0.2,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"AI explanation failed: {str(e)}"

def explain_file(file_context: dict) -> str:
    system_prompt = """
You are a senior telecom NOC engineer.

Explain the PCAP analysis at FILE LEVEL.
Rules:
- Do NOT analyze packets.
- Use only provided analysis.
- Be concise but insightful.
- Highlight dominant failure.
- Use professional telecom language.
"""

    response = client.chat.completions.create(
        model="gpt-4o",  
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(file_context, indent=2)}
        ],
        temperature=0.2
    )

    return response.choices[0].message.content.strip()
