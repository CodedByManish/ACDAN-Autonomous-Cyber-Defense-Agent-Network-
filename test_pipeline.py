"""
ACDAN Integration Test Script

This script tests the full pipeline of the ACDAN system:
1. Detection Service
2. Reasoning Engine
3. Response Engine (RL Agent)

"""

import requests

BASE_URL = "httpcls://127.0.0.1:8000/api"


def send_request(endpoint: str, payload: dict) -> dict:
    """Send POST request to API and return JSON response."""
    try:
        response = requests.post(f"{BASE_URL}/{endpoint}", json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] Request to {endpoint} failed: {exc}")
        return {}


def test_full_system_flow():
    """Run an end-to-end integration test for the ACDAN pipeline."""

    print("\n========== ACDAN FULL PIPELINE TEST ==========\n")

    # Mock network packet (simulated DoS traffic)
    packet_data = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 1000,
        "dst_bytes": 0,
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.5"
    }

    # ------------------------------------------------
    # Phase 2: Detection
    # ------------------------------------------------
    print("[PHASE 2] Detection Service")

    detection = send_request("detection/analyze/", packet_data)

    if not detection:
        print("[FAILED] Detection service did not return a valid response.")
        return

    predicted_class = detection.get("predicted_class", "Unknown")
    confidence = detection.get("confidence", "N/A")
    threat_level = detection.get("threat_level", "LOW")

    print(f"Prediction   : {predicted_class}")
    print(f"Confidence   : {confidence}")
    print(f"Threat Level : {threat_level}")

    # ------------------------------------------------
    # Phase 3: Reasoning (LLM)
    # ------------------------------------------------
    if threat_level != "LOW":

        print("\n[PHASE 3] Reasoning Engine")

        reasoning = send_request("reasoning/reason/", detection)

        if not reasoning:
            print("[FAILED] Reasoning service did not return a valid response.")
            return

        summary = reasoning.get("threat_summary", "No summary available")
        risk_level = reasoning.get("risk_level", "HIGH")

        print(f"Risk Level : {risk_level}")
        print(f"Summary    : {summary[:120]}...")

        # ------------------------------------------------
        # Phase 4: Response (RL Agent)
        # ------------------------------------------------
        print("\n[PHASE 4] Response Engine")

        response_payload = {"risk_level": risk_level}
        response = send_request("response/execute/", response_payload)

        if not response:
            print("[FAILED] Response service did not return a valid response.")
            return

        action = response.get("action", "No action returned")

        print(f"Mitigation Action : {action}")

    else:
        print("\n[INFO] Threat level LOW — Reasoning and Response phases skipped.")

    print("\n========== TEST COMPLETED ==========\n")


if __name__ == "__main__":
    test_full_system_flow()