import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a senior telecom core network engineer.
Explain SIP call failures clearly and practically.
Do not invent facts. Use only provided data.
"""

def explain_call(call):
    user_prompt = f"""
SIP Call Analysis:
Outcome: {call['outcome']}
Root Cause Hint: {call['root_cause']}
Events: {call['events']}

Explain:
1. What happened
2. Why it likely happened
3. What an engineer should check
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2
    )

    return response.choices[0].message.content
