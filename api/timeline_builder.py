from typing import List, Dict, Any


def build_timeline(
    events: List[Dict[str, Any]],
    rtp_packets: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    MVP-1 Timeline Builder
    - Full SIP signaling
    - Sampled RTP presence (not quality)
    """

    timeline: List[Dict[str, Any]] = []

    # -----------------------------
    # SIP events (full fidelity)
    # -----------------------------
    for e in events:
        if e.get("method"):
            label = e["method"]
        elif e.get("status"):
            label = f"SIP {e['status']}"
        else:
            label = "SIP"

        timeline.append({
            "time": e["time"],
            "type": "SIP",
            "label": label,
            "packet": e["frame"]
        })

    # -----------------------------
    # RTP events (sampled, MVP-1)
    # -----------------------------
    if rtp_packets:
        # First RTP packet
        first_rtp = rtp_packets[0]
        timeline.append({
            "time": first_rtp["time"],
            "type": "RTP",
            "label": "RTP started",
            "packet": first_rtp["frame"]
        })

        # Last RTP packet
        last_rtp = rtp_packets[-1]
        if last_rtp["frame"] != first_rtp["frame"]:
            timeline.append({
                "time": last_rtp["time"],
                "type": "RTP",
                "label": "RTP ended",
                "packet": last_rtp["frame"]
            })

    # -----------------------------
    # Stable ordering
    # -----------------------------
    timeline.sort(key=lambda x: (x["time"], x["packet"]))

    return timeline
