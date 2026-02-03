"use client";

const API = process.env.NEXT_PUBLIC_API_URL;


console.log("API URL =", API);


import { useState } from "react";



type Message = {
  role: "system" | "user" | "assistant";
  content: string;
};

export default function Home() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "👋 Upload a PCAP file to begin analysis."
    }
  ]);

  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [input, setInput] = useState("");

  async function uploadPcap() {
    if (!file) return;
  
    setMessages(m => [
      ...m,
      { role: "user", content: `📁 Uploaded ${file.name}` }
    ]);
  
    const form = new FormData();
    form.append("file", file);
  
    let res;
    try {
      res = await fetch(`${API}/analyze/sip`, {
        method: "POST",
        body: form
      });
    } catch (e) {
      setMessages(m => [
        ...m,
        { role: "assistant", content: "❌ Cannot reach backend API." }
      ]);
      return;
    }
  
    if (!res.ok) {
      const text = await res.text();
      setMessages(m => [
        ...m,
        {
          role: "assistant",
          content: `❌ Backend error (${res.status}):\n${text}`
        }
      ]);
      return;
    }
  
    const data = await res.json();
    setJobId(data.job_id);
  
    setMessages(m => [
      ...m,
      {
        role: "assistant",
        content:
                  `✅ Analysis complete.

                  📄 File overview:
                  - Total packets: ${data.packet_stats.total_packets}
                  - SIP packets: ${data.packet_stats.sip_packets}
                  - RTP packets: ${data.packet_stats.rtp_packets}

                  📞 Calls:
                  - Total: ${data.total_calls}


                  🧠 AI Insight:
                  ${data.file_ai_insight}
                  `+`You can now ask questions about this PCAP.`
      }
    ]);
  }
  

  async function sendMessage() {
    if (!input || !jobId) return;

    const question = input;
    setInput("");

    setMessages(m => [...m, { role: "user", content: question }]);

    const res = await fetch(`${API}/chat/${jobId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question })
    });

    const data = await res.json();

    setMessages(m => [
      ...m,
      { role: "assistant", content: data.answer }
    ]);
  }

  return (
    <div style={{
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      fontFamily: "sans-serif"
    }}>
      <header style={{
        padding: 16,
        borderBottom: "1px solid #ddd",
        fontWeight: "bold"
      }}>
        PCAP AI Reader
      </header>

      <main style={{
        flex: 1,
        padding: 16,
        overflowY: "auto",
        background: "#f7f7f8"
      }}>
        {messages.map((m, i) => (
          <div
            key={i}
            style={{
              marginBottom: 12,
              whiteSpace: "pre-wrap",
              background: m.role === "assistant" ? "#fff" : "#dcfce7",
              padding: 12,
              borderRadius: 8,
              maxWidth: "80%"
            }}
          >
            {m.content}
          </div>
        ))}
      </main>

      <footer style={{
      padding: 12,
      borderTop: "1px solid #ddd",
      display: "flex",
      alignItems: "center",
      gap: 8,
      background: "#fff"
    }}>
      {!jobId && (
        <>
          <input
            type="file"
            onChange={e => setFile(e.target.files?.[0] || null)}
          />
          <button onClick={uploadPcap}>📎 Upload PCAP</button>
        </>
      )}

      {jobId && (
        <>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === "Enter") sendMessage();
            }}
            placeholder="Type a message…"
            style={{
              flex: 1,
              padding: "10px",
              borderRadius: "20px",
              border: "1px solid #ccc"
            }}
          />
          <button
            onClick={sendMessage}
            style={{
              padding: "10px 16px",
              borderRadius: "20px",
              background: "#10a37f",
              color: "#fff",
              border: "none"
            }}
          >
            Send
          </button>
        </>
      )}
    </footer>
    </div>
  );
}
