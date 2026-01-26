import subprocess

PCAP_FILE = "trimmed.pcapng"

def get_protocol_hierarchy():
    cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-q",
        "-z", "io,phs"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("ERROR running tshark:")
        print(result.stderr)
        return ""

    return result.stdout


def detect_context(phs_output: str):
    phs_lower = phs_output.lower()

    protocols = []

    # --- Wi-Fi / Air side detection ---
    if any(x in phs_lower for x in ["radiotap", "wlan_radio", "wlan"]):
        protocols.append("802.11")

    # --- IP layer ---
    if "internet protocol version 4" in phs_lower or " ip " in phs_lower:
        protocols.append("IPv4")
    if "internet protocol version 6" in phs_lower:
        protocols.append("IPv6")

    # --- Transport ---
    if "transmission control protocol" in phs_lower:
        protocols.append("TCP")
    if "user datagram protocol" in phs_lower:
        protocols.append("UDP")

    # --- Telecom / Core ---
    if "sip" in phs_lower:
        protocols.append("SIP")
    if "rtp" in phs_lower:
        protocols.append("RTP")
    if "gtp" in phs_lower:
        protocols.append("GTP")
    if "sctp" in phs_lower:
        protocols.append("SCTP")

    # --- Context classification ---
    if "802.11" in protocols:
        context = "WIFI_AIR"
        telecom_relevant = False
        reason = "Wi-Fi air-side capture (radiotap / wlan frames detected)."

    elif any(p in protocols for p in ["SIP", "RTP", "GTP", "SCTP"]):
        context = "IMS_CORE"
        telecom_relevant = True
        reason = "Core telecom signaling detected."

    elif any(p in protocols for p in ["TCP", "UDP"]):
        context = "TRANSPORT_IP"
        telecom_relevant = False
        reason = "Generic IP transport capture."

    else:
        context = "UNKNOWN"
        telecom_relevant = False
        reason = "Unable to classify capture."

    return {
        "capture_context": context,
        "protocols_detected": sorted(set(protocols)),
        "telecom_relevant": telecom_relevant,
        "reason": reason
    }


def main():
    phs_output = get_protocol_hierarchy()
    print("===== Protocol Hierarchy =====")
    print(phs_output)

    context_info = detect_context(phs_output)

    print("===== CONTEXT DETECTION RESULT =====")
    for k, v in context_info.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()

