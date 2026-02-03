from typing import Dict, List, Any, Tuple
from tshark_runner import run_tshark


RTP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "rtp.ssrc"
]


def extract_rtp_packets(pcap_file: str) -> List[Dict[str, Any]]:
    args = [
        "-r", pcap_file,
        "-Y", "rtp",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]

    for f in RTP_FIELDS:
        args += ["-e", f]

    result = run_tshark(args)

    packets = []
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(RTP_FIELDS):
            continue

        frame, time_rel, src, dst, sport, dport, ssrc = parts

        packets.append({
            "frame": int(frame),
            "time": float(time_rel),
            "src": src,
            "dst": dst,
            "src_port": int(sport) if sport else None,
            "dst_port": int(dport) if dport else None,
            "ssrc": ssrc or None
        })

    return packets

def analyze_rtp_direction(rtp_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not rtp_packets:
        return {
            "rtp_present": False,
            "direction": "NONE",
            "inference": "No RTP detected → media did not start"
        }

    directions = set()
    endpoints = set()

    for pkt in rtp_packets:
        endpoints.add(pkt["src"])
        endpoints.add(pkt["dst"])
        directions.add((pkt["src"], pkt["dst"]))

    if len(directions) > 1:
        direction = "BIDIRECTIONAL"
        inference = "RTP flowing in both directions"
    else:
        direction = "ONE_WAY"
        inference = "One-way RTP detected (possible NAT / routing issue)"

    return {
        "rtp_present": True,
        "direction": direction,
        "total_packets": len(rtp_packets),
        "endpoints": sorted(endpoints),
        "inference": inference
    }

def main():
    import sys, json

    if len(sys.argv) < 2:
        print("Usage: python rtp_parser.py <pcap>")
        sys.exit(1)

    pcap = sys.argv[1]
    packets = extract_rtp_packets(pcap)
    result = analyze_rtp_direction(packets)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

