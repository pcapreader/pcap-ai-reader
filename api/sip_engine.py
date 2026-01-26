from typing import List, Dict
from sip_parser import (
    run_tshark_sip_json,
    extract_sip_calls,
    build_call_summary
)

def analyze_sip_pcap(pcap_path: str) -> List[Dict]:
    packets = run_tshark_sip_json(pcap_path)
    calls = extract_sip_calls(packets)

    summaries = []
    for call_id, events in calls.items():
        summaries.append(build_call_summary(call_id, events))

    return summaries
