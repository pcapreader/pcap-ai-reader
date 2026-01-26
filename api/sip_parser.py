import subprocess
import json

#PCAP_FILE = "sip.pcapng"


def run_tshark_sip_json(pcap_file):
    cmd = [
        "tshark",
        "-r", pcap_file,
        "-Y", "sip",
        "-T", "json"
    ]
    ...


    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return json.loads(result.stdout)


def get_first(dct, keys):
    """Return first existing key value from dict"""
    for k in keys:
        if k in dct:
            return dct[k]
    return None


def extract_sip_calls(packets):
    calls = {}

    for pkt in packets:
        layers = pkt["_source"]["layers"]
        sip = layers.get("sip", {})

        # ---- Call-ID (robust) ----
        hdr = sip.get("sip.msg_hdr_tree", {})
        call_id = get_first(
            hdr,
            ["sip.Call-ID", "sip.call_id_generated"]
        )

        if not call_id:
            continue

        # ---- Method (INVITE / BYE / ACK) ----
        req_tree = sip.get("sip.Request-Line_tree", {})
        method = req_tree.get("sip.Method")

        # ---- Status Code (for responses) ----
        status = get_first(
            sip,
            ["sip.Status-Code", "sip.Status-Line"]
        )

        # ---- Timestamp ----
        frame = layers.get("frame", {})
        time = frame.get("frame.time")

        calls.setdefault(call_id, []).append({
            "time": time,
            "method": method,
            "status": status
        })

    return calls

def classify_call(events):
    methods = [e["method"] for e in events if e["method"]]
    statuses = [e["status"] for e in events if e["status"]]

    has_invite = "INVITE" in methods
    has_ack = "ACK" in methods
    has_200 = any("200" in s for s in statuses)
    has_ringing = any("180" in s for s in statuses)
    failure_status = next((s for s in statuses if any(x in s for x in ["4", "5", "6"])), None)

    if has_invite and has_200 and has_ack:
        return "SUCCESS", "Call established normally"

    if failure_status:
        return "FAILED_EARLY", f"SIP failure response: {failure_status}"

    if has_ringing and not has_200:
        return "NO_ANSWER", "Ringing seen but no 200 OK"

    if has_200 and not has_ack:
        return "DROP_AFTER_200", "200 OK seen but ACK missing"

    if has_invite:
        return "INCOMPLETE", "INVITE seen but call flow incomplete"

    return "UNKNOWN", "Unable to classify call"

def map_root_cause(outcome, reason, events):
    statuses = [e["status"] for e in events if e["status"]]

    if outcome == "SUCCESS":
        return "No issue detected"

    if outcome == "NO_ANSWER":
        return "Called party did not answer (alerting without connect)"

    if outcome == "DROP_AFTER_200":
        return (
            "ACK missing after 200 OK. Possible causes: "
            "firewall/NAT blocking, SBC issue, packet loss, asymmetric routing"
        )

    if outcome == "FAILED_EARLY":
        for s in statuses:
            if "4" in s:
                return "Client-side SIP failure (busy, forbidden, invalid number)"
            if "5" in s:
                return "Server/network-side failure (SBC, routing, overload)"
            if "6" in s:
                return "Global SIP failure (call rejected everywhere)"

    if outcome == "INCOMPLETE":
        return "Incomplete capture or signaling loss"

    return "Unknown cause"

def build_call_summary(call_id, events):
    outcome, reason = classify_call(events)
    root_cause = map_root_cause(outcome, reason, events)

    return {
        "call_id": call_id,
        "outcome": outcome,
        "reason": reason,
        "root_cause": root_cause,
        "events": events
    }



def main():
    packets = run_tshark_sip_json()
    calls = extract_sip_calls(packets)

    print(f"Total SIP calls found: {len(calls)}")

    summaries = []
    for call_id, events in calls.items():
        summaries.append(build_call_summary(call_id, events))

    print(json.dumps(summaries, indent=2))



if __name__ == "__main__":
    main()
