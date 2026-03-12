"""
ACDAN Pipeline Integration Test Script

This script validates the end-to-end communication between:
1. Detection (ML Inference)
2. Reasoning (LLM + RAG Context)
3. Response (RL Action Selection)
"""

import requests
import json
import sys

# Configuration
BASE_URL = "http://127.0.0.1:8000/api"
TIMEOUT = 30  # Increased for LLM processing time

def send_request(endpoint: str, payload: dict) -> dict:
    """Send POST request to ACDAN API and return JSON response."""
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"CRITICAL: Request to {url} failed.")
        print(f"Details: {exc}")
        return {}

def test_full_system_flow():
    """Execute end-to-end integration test."""

    print("-" * 50)
    print("ACDAN SYSTEM INTEGRATION TEST")
    print("-" * 50)

    # 1. SIMULATED PACKET DATA (CIC-IDS-2017 Format)
    # Using features your model was trained on (e.g., Destination Port, Flow Duration)
    packet_data = {
        "Destination Port": 80,
        "Flow Duration": 1293792,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 7,
        "Total Length of Fwd Packets": 26,
        "Total Length of Bwd Packets": 11607,
        "Fwd Packet Length Mean": 8.666666667,
        "Bwd Packet Length Mean": 1658.142857,
        "Flow Bytes/s": 8991.398927,
        "Flow Packets/s": 7.72921768,
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.5",
        "protocol": "TCP"
    }

    # ------------------------------------------------
    # PHASE 2: DETECTION
    # ------------------------------------------------
    print("\n[PHASE 2] Initiating ML Detection...")
    
    # Endpoint based on path('api/detection/', include('apps.detection.urls'))
    detection_results = send_request("detection/analyze/", packet_data)

    if not detection_results or "error" in detection_results:
        print("FAILURE: Detection Service Error.")
        return

    predicted_class = detection_results.get("predicted_class", "Unknown")
    confidence = detection_results.get("confidence", 0.0)
    threat_level = detection_results.get("threat_level", "LOW")

    print(f"Result      : {predicted_class}")
    print(f"Confidence  : {confidence:.4f}")
    print(f"Threat Level: {threat_level}")

    # ------------------------------------------------
    # PHASE 3: REASONING (LLM + RAG)
    # ------------------------------------------------
    if threat_level != "LOW":
        print("\n[PHASE 3] Initiating LLM Reasoning and RAG Lookup...")

        # Payload includes detection output to provide context to the LLM
        reasoning_results = send_request("reasoning/reason/", detection_results)

        if not reasoning_results or "error" in reasoning_results:
            print("FAILURE: Reasoning Service Error.")
            return

        summary = reasoning_results.get("threat_summary", "No summary provided")
        risk_level = reasoning_results.get("risk_level", "UNKNOWN")
        
        # Check if RAG/CVE analysis was included
        cve_info = reasoning_results.get("cve_analysis", "No CVE context found")

        print(f"Risk Assessment: {risk_level}")
        print(f"Summary        : {summary[:150]}...")
        
        if "cve_analysis" in reasoning_results:
            print("RAG Status     : Context successfully retrieved from FAISS index.")

        # ------------------------------------------------
        # PHASE 4: RESPONSE (RL AGENT)
        # ------------------------------------------------
        print("\n[PHASE 4] Executing Response Mitigation...")

        response_payload = {
            "predicted_class": predicted_class,
            "risk_level": risk_level
        }
        
        mitigation_results = send_request("response/execute/", response_payload)

        if not mitigation_results or "error" in mitigation_results:
            print("FAILURE: Response Service Error.")
            return

        action = mitigation_results.get("action", "No action determined")
        print(f"Mitigation Action: {action}")

    else:
        print("\nSYSTEM NOTICE: Threat level is LOW. Reasoning and Response bypassed.")

    print("\n" + "-" * 50)
    print("TEST SEQUENCE COMPLETED")
    print("-" * 50)

if __name__ == "__main__":
    test_full_system_flow()