import sys
import json
import subprocess
import shutil
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


class TsharkError(RuntimeError):
    pass


@dataclass
class TsharkResult:
    cmd: List[str]
    stdout: str
    stderr: str
    returncode: int


def ensure_tshark_available() -> str:
    """
    Ensures tshark is installed and on PATH.
    Returns the resolved tshark path.
    """
    path = shutil.which("tshark")
    if not path:
        raise TsharkError("tshark not found. Install Wireshark (includes tshark) and ensure it is on PATH.")
    return path


def run_tshark(cmd_args: List[str], timeout_sec: int = 180, check: bool = True) -> TsharkResult:
    """
    Generic tshark runner for API use.
    cmd_args: tshark arguments ONLY (do not include 'tshark' itself).
    """
    tshark_path = ensure_tshark_available()
    cmd = [tshark_path] + cmd_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec
        )
    except subprocess.TimeoutExpired as e:
        raise TsharkError(f"tshark timed out after {timeout_sec}s: {' '.join(cmd)}") from e

    out = TsharkResult(
        cmd=cmd,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
        returncode=result.returncode
    )

    if check and out.returncode != 0:
        raise TsharkError(
            f"ERROR running tshark (code={out.returncode})\n"
            f"CMD: {' '.join(cmd)}\n"
            f"STDERR:\n{out.stderr.strip()}"
        )

    return out


def get_protocol_hierarchy(pcap_path: str) -> str:
    """
    Returns tshark protocol hierarchy stats output (io,phs).
    """
    res = run_tshark(
        [
            "-r", pcap_path,
            "-q",
            "-z", "io,phs",
        ],
        timeout_sec=180,
        check=True
    )
    return res.stdout


def detect_context(phs_output: str) -> Dict[str, Any]:
    """
    Your existing context detection logic, unchanged, but returns structured dict.
    """
    phs_lower = (phs_output or "").lower()
    protocols: List[str] = []

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


def analyze_capture_context(pcap_path: str) -> Dict[str, Any]:
    """
    API-friendly helper:
    1) runs io,phs
    2) returns context detection + raw phs output
    """
    phs_output = get_protocol_hierarchy(pcap_path)
    context_info = detect_context(phs_output)

    return {
        "pcap_path": pcap_path,
        "protocol_hierarchy_raw": phs_output,
        "context": context_info
    }

def get_packet_counts(pcap_file: str) -> Dict[str, Any]:
    """
    Reliable packet counts:
    - total packets = number of frames
    - sip packets = frames where sip filter matches
    - rtp packets = frames where rtp filter matches
    """

    # Total frames
    total_frames_res = run_tshark([
        "-r", pcap_file,
        "-T", "fields",
        "-e", "frame.number"
    ])
    total_packets = len([x for x in total_frames_res.stdout.splitlines() if x.strip()])

    # SIP frames
    sip_res = run_tshark([
        "-r", pcap_file,
        "-Y", "sip",
        "-T", "fields",
        "-e", "frame.number"
    ])
    sip_packets = len([x for x in sip_res.stdout.splitlines() if x.strip()])

    # RTP frames
    rtp_res = run_tshark([
        "-r", pcap_file,
        "-Y", "rtp",
        "-T", "fields",
        "-e", "frame.number"
    ])
    rtp_packets = len([x for x in rtp_res.stdout.splitlines() if x.strip()])

    return {
        "total_packets": total_packets,
        "sip_packets": sip_packets,
        "rtp_packets": rtp_packets
    }



def main():


    if len(sys.argv) < 2:
        print("Usage: python tshark_runner.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    try:
        result = analyze_capture_context(pcap_path)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
