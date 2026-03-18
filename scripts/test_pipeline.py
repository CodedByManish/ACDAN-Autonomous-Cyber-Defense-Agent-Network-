import requests
import json
import time

# Configuration
BASE_URL = "http://127.0.0.1:8000/api"
TIMEOUT = 200  # LLMs/RL models take time to initialize and process

def send_request(endpoint: str, payload: dict) -> dict:
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"CRITICAL: Request to {url} failed.")
        if hasattr(exc, 'response') and exc.response is not None:
            print(f"Status Code: {exc.response.status_code}")
            print(f"Response: {exc.response.text}")
        return {}

def test_full_system_flow():
    print("=" * 60)
    print("      ACDAN END-TO-END SYSTEM INTEGRATION TEST")
    print("=" * 60)

    # 1. SIMULATED NETWORK ATTACK DATA
    payload = {
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.5",
        "protocol": "TCP",
        "port": 80,
        "duration": 1293792,
        "features": {
            "Destination Port": 80, "Flow Duration": 1293792, "Total Fwd Packets": 3,
            "Total Backward Packets": 7, "Total Length of Fwd Packets": 26,
            "Total Length of Bwd Packets": 11607, "Fwd Packet Length Max": 8.6,
            "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 8.6,
            "Fwd Packet Length Std": 0, "Bwd Packet Length Max": 1658,
            "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 1658,
            "Bwd Packet Length Std": 0, "Flow Bytes/s": 8991.3,
            "Flow Packets/s": 7.7, "Flow IAT Mean": 215632, "Flow IAT Std": 534,
            "Flow IAT Max": 1293, "Flow IAT Min": 3, "Fwd IAT Total": 1293,
            "Fwd IAT Mean": 646, "Fwd IAT Std": 0, "Fwd IAT Max": 1293,
            "Fwd IAT Min": 3, "Bwd IAT Total": 1100, "Bwd IAT Mean": 180,
            "Bwd IAT Std": 0, "Bwd IAT Max": 500, "Bwd IAT Min": 5,
            "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0,
            "Bwd URG Flags": 0, "Fwd Header Length": 72, "Bwd Header Length": 152,
            "Fwd Packets/s": 2.3, "Bwd Packets/s": 5.4, "Min Packet Length": 0,
            "Max Packet Length": 1658, "Packet Length Mean": 1163,
            "Packet Length Std": 500, "Packet Length Variance": 2500,
            "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "PSH Flag Count": 1, "ACK Flag Count": 0, "URG Flag Count": 0,
            "CWE Flag Count": 0, "ECE Flag Count": 0, "Down/Up Ratio": 2,
            "Average Packet Size": 1100, "Avg Fwd Segment Size": 8.6,
            "Avg Bwd Segment Size": 1658, "Fwd Header Length.1": 72,
            "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": 3, "Subflow Fwd Bytes": 26, "Subflow Bwd Packets": 7,
            "Subflow Bwd Bytes": 11607, "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 255, "act_data_pkt_fwd": 1,
            "min_seg_size_forward": 20, "Active Mean": 0, "Active Std": 0,
            "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0,
            "Idle Max": 0, "Idle Min": 0
        }
    }

    # ------------------------------------------------
    # PHASE 1: DETECTION (ML)
    # ------------------------------------------------
    print("\n[PHASE 1] Initiating ML Detection...")
    start_time = time.time()
    detection_results = send_request("detection/analyze", payload)

    if not detection_results: return

    is_threat = detection_results.get("is_threat", False)
    threat_type = detection_results.get("threat_type", "Unknown")
    confidence = detection_results.get("confidence_score", 0.0)

    print(f"  > Result      : {'🚨 THREAT' if is_threat else '✅ BENIGN'}")
    print(f"  > Type        : {threat_type}")
    print(f"  > Confidence  : {confidence:.4f}")
    print(f"  > Process Time: {time.time() - start_time:.2f}s")

    # ------------------------------------------------
    # PHASE 2: REASONING (LLM + RAG)
    # ------------------------------------------------
    if is_threat:
        print("\n[PHASE 2] Initiating LLM Reasoning & RAG Lookup...")
        
        reasoning_payload = {
            "predicted_class": threat_type,
            "confidence": confidence,
            "threat_level": "HIGH" if confidence > 0.8 else "MEDIUM"
        }
        
        start_time = time.time()
        reasoning_results = send_request("reasoning/reason", reasoning_payload)

        if not reasoning_results: return

        risk_level = reasoning_results.get('risk_level', 'MEDIUM')
        print(f"  > Risk Level   : {risk_level}")
        print(f"  > RAG Context  : {reasoning_results.get('cve_context_used')}")
        print(f"\n  > AI SUMMARY   :")
        print(f"    {reasoning_results.get('threat_summary')}")
        
        print(f"\n  > Process Time: {time.time() - start_time:.2f}s")

        # ------------------------------------------------
        # PHASE 3: RESPONSE (RL AGENT)
        # ------------------------------------------------
        print("\n[PHASE 3] Initiating RL Response Agent...")
        
        response_payload = {
            "predicted_class": threat_type,
            "risk_level": risk_level
        }
        
        start_time = time.time()
        response_results = send_request("response/execute", response_payload)

        if response_results:
            print(f"  > RL DECISION  : 🛡️ {response_results.get('recommended_action')}")
            print(f"  > Confidence   : {response_results.get('confidence_score')}")
            print(f"  > Rationale    : {response_results.get('rationale')}")
            print(f"  > System Load  : {response_results.get('impact_on_system')}")
            print(f"  > Process Time : {time.time() - start_time:.2f}s")
            
    else:
        print("\nResult: BENIGN - System remains in monitoring mode.")

    print("\n" + "=" * 60)
    print("              TEST SEQUENCE COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    test_full_system_flow()