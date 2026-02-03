from typing import Dict, Any, List
import os

from sip_parser import (
    extract_sip_packets,
    extract_sip_calls,
    build_call_summary
)
from rtp_parser import extract_rtp_packets, analyze_rtp_direction
from timeline_builder import build_timeline
from pcap_exporter import export_failing_call
from file_summary import build_file_summary
from tshark_runner import get_packet_counts


def analyze_pcap_calls(pcap_file: str) -> Dict[str, Any]:
    """
    MVP-1 PCAP Analyzer

    Responsibilities:
    - SIP signaling analysis (source of truth)
    - RTP presence + direction (no quality yet)
    - Timeline construction
    - Export failing calls
    - File-level summary + packet stats
    """

    # -----------------------------
    # 1️⃣ SIP analysis (SOURCE OF TRUTH)
    # -----------------------------
    sip_packets = extract_sip_packets(pcap_file)
    sip_calls = extract_sip_calls(sip_packets)

    # -----------------------------
    # 2️⃣ RTP packets (parsed once)
    # -----------------------------
    all_rtp_packets = extract_rtp_packets(pcap_file)

    final_calls: List[Dict[str, Any]] = []

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    # -----------------------------
    # 3️⃣ Per-call processing
    # -----------------------------
    for call_id, events in sip_calls.items():
        if not events:
            continue  # safety guard

        summary = build_call_summary(call_id, events)

        # ---- SIP time window ----
        start_time = events[0]["time"]
        end_time = events[-1]["time"]

        # ---- RTP scoped to SIP window ----
        rtp_packets = [
            r for r in all_rtp_packets
            if start_time <= r["time"] <= end_time
        ]

        rtp_result = analyze_rtp_direction(rtp_packets)

        # -----------------------------
        # 4️⃣ Final verdict logic (LOCKED FOR MVP-1)
        # -----------------------------
        if summary.get("failure_packet"):
            final_verdict = "SIP_FAILURE"
            protocol = "SIP"
            failure_stage = "SIP"

        elif not rtp_result["rtp_present"]:
            final_verdict = "MEDIA_FAILURE"
            protocol = "RTP"
            failure_stage = "RTP"

        elif rtp_result["direction"] == "ONE_WAY":
            final_verdict = "MEDIA_DEGRADED"
            protocol = "RTP"
            failure_stage = "RTP"

        else:
            final_verdict = "SUCCESS"
            protocol = "NONE"
            failure_stage = "NONE"

        # -----------------------------
        # 5️⃣ Timeline (SIP + sampled RTP)
        # -----------------------------
        timeline = build_timeline(events, rtp_packets)

        # -----------------------------
        # 6️⃣ Export failing calls only
        # -----------------------------
        export_info = {"pcap_available": False}

        if final_verdict != "SUCCESS":
            export_info = export_failing_call(
                pcap_file=pcap_file,
                call_id=call_id,
            )

        final_calls.append({
            "call_id": call_id,
            "final_verdict": final_verdict,
            "root_cause": summary.get("root_cause"),
            "failure_stage": failure_stage,
            "protocol_responsible": protocol,
            "invite_packet": summary.get("invite_packet"),
            "ok_200_packet": summary.get("ok_200_packet"),
            "failure_packet": summary.get("failure_packet"),
            "invite_to_200_latency_sec": summary.get("invite_to_200_latency_sec"),
            "rtp": rtp_result,
            "timeline": timeline,
            "export": export_info
        })

    # -----------------------------
    # 7️⃣ FILE-LEVEL METRICS
    # -----------------------------
    file_summary = build_file_summary({
        "calls": final_calls
    })

    packet_stats = get_packet_counts(pcap_file)

    # -----------------------------
    # 8️⃣ Final response (API + AI ready)
    # -----------------------------
    return {
        "pcap": pcap_file,
        "file_summary": file_summary,
        "packet_stats": packet_stats,
        "total_calls": len(final_calls),
        "calls": final_calls
    }
