from typing import List, Dict, Any
from sip_parser import (
    extract_sip_packets,
    extract_sip_calls,
    build_call_summary
)


def analyze_sip_pcap(pcap_path: str) -> List[Dict[str, Any]]:
    """
    SIP-only analysis engine.
    Returns one summary per Call-ID.
    """
    sip_packets = extract_sip_packets(pcap_path)
    sip_calls = extract_sip_calls(sip_packets)

    summaries: List[Dict[str, Any]] = []
    for call_id, events in sip_calls.items():
        summaries.append(build_call_summary(call_id, events))

    return summaries
