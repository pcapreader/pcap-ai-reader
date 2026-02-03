import sys
import json
from typing import Dict, List, Any
from tshark_runner import run_tshark


SIP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code"
]


# -----------------------------
# 1️⃣ Extract SIP packets
# -----------------------------
def extract_sip_packets(pcap_file: str) -> List[Dict[str, Any]]:
    args = [
        "-r", pcap_file,
        "-Y", "sip",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]

    for f in SIP_FIELDS:
        args += ["-e", f]

    result = run_tshark(args)

    packets: List[Dict[str, Any]] = []

    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(SIP_FIELDS):
            continue

        frame_no, time_rel, call_id, method, status = parts

        if not call_id:
            continue

        packets.append({
            "frame": int(frame_no),
            "time": float(time_rel),
            "call_id": call_id.strip(),
            "method": method or None,
            "status": status or None
        })

    return packets


# -----------------------------
# 2️⃣ Group packets by Call-ID
# -----------------------------
def extract_sip_calls(packets: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    calls: Dict[str, List[Dict]] = {}

    for pkt in packets:
        calls.setdefault(pkt["call_id"], []).append(pkt)

    for call_id in calls:
        calls[call_id].sort(key=lambda x: (x["time"], x["frame"]))

    return calls


# -----------------------------
# 3️⃣ SIP failure classification (FACTS ONLY)
# -----------------------------
def classify_call(events: List[Dict]) -> Dict[str, Any]:
    invite = next((e for e in events if e["method"] == "INVITE"), None)
    ok_200 = next((e for e in events if e["status"] == "200"), None)
    ack = next((e for e in events if e["method"] == "ACK"), None)

    failure_status = next(
        (e for e in events if e["status"] and e["status"].startswith(("4", "5", "6"))),
        None
    )

    # SIP error response
    if failure_status:
        return {
            "root_cause": f"SIP failure response {failure_status['status']}",
            "failure_packet": failure_status["frame"]
        }

    # Missing ACK after 200 OK
    if ok_200 and not ack:
        return {
            "root_cause": "ACK missing after 200 OK",
            "failure_packet": ok_200["frame"]
        }

    # No explicit SIP failure
    return {
        "root_cause": "SIP signaling completed without explicit failure",
        "failure_packet": None
    }


# -----------------------------
# 4️⃣ Build per-call summary (MVP-1 contract)
# -----------------------------
def build_call_summary(call_id: str, events: List[Dict]) -> Dict[str, Any]:
    classification = classify_call(events)

    invite = next((e for e in events if e["method"] == "INVITE"), None)
    ok_200 = next((e for e in events if e["status"] == "200"), None)

    latency = None
    if invite and ok_200:
        latency = round(ok_200["time"] - invite["time"], 3)

    return {
        "call_id": call_id,
        "root_cause": classification["root_cause"],
        "invite_packet": invite["frame"] if invite else None,
        "ok_200_packet": ok_200["frame"] if ok_200 else None,
        "failure_packet": classification.get("failure_packet"),
        "invite_to_200_latency_sec": latency,
        "events": events
    }


# -----------------------------
# CLI test (optional)
# -----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python sip_parser.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    packets = extract_sip_packets(pcap_file)
    calls = extract_sip_calls(packets)

    summaries = []
    for call_id, events in calls.items():
        summaries.append(build_call_summary(call_id, events))

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
