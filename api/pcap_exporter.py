from tshark_runner import run_tshark
import os

OUTPUT_DIR = "output"


def export_failing_call(pcap_file: str, call_id: str):
    """
    MVP-1 exporter
    Exports SIP + RTP packets related to a Call-ID
    """

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_pcap = os.path.join(
        OUTPUT_DIR,
        f"{call_id}_failing.pcap"
    )

    args = [
        "-r", pcap_file,
        "-Y", f'sip.Call-ID == "{call_id}" or rtp',
        "-w", output_pcap
    ]

    try:
        run_tshark(args)
        return {
            "pcap_available": True,
            "path": output_pcap
        }
    except Exception as e:
        return {
            "pcap_available": False,
            "reason": str(e)
        }
