from typing import Dict, Any


def build_file_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    calls = analysis["calls"]

    total_calls = len(calls)

    sip_failures = sum(1 for c in calls if c["final_verdict"] == "SIP_FAILURE")
    media_failures = sum(1 for c in calls if c["final_verdict"] == "MEDIA_FAILURE")
    success_calls = sum(1 for c in calls if c["final_verdict"] == "SUCCESS")

    dominant_failure = None
    if sip_failures > media_failures:
        dominant_failure = "SIP"
    elif media_failures > 0:
        dominant_failure = "MEDIA"

    return {
        "total_calls": total_calls,
        "success_calls": success_calls,
        "sip_failures": sip_failures,
        "media_failures": media_failures,
        "dominant_failure_domain": dominant_failure,
        "overall_verdict": (
            "HEALTHY" if success_calls == total_calls
            else "DEGRADED" if media_failures > 0
            else "FAILED"
        )
    }
