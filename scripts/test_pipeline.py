import requests
import json
import time

# Configuration
# Removed '/api' prefix because your FastAPI routers define their own prefixes
BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 300 

def send_request(endpoint: str, payload: dict) -> dict:
    # Ensure no double slashes and correct pathing
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    try:
        print(f"📡 Sending request to: {url}")
        response = requests.post(url, json=payload, timeout=TIMEOUT)
        
        if response.status_code == 500:
            print(f"❌ SERVER ERROR (500): Check Terminal 1 logs for the Python Traceback.")
            print(f"Details: {response.text}")
            return {}
            
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"💥 CONNECTION FAILED: {exc}")
        if hasattr(exc, 'response') and exc.response is not None:
            print(f"Status Code: {exc.response.status_code}")
            print(f"Response: {exc.response.text}")
        return {}

def test_full_system_flow():
    print("=" * 60)
    print("      ACDAN END-TO-END SYSTEM INTEGRATION TEST")
    print("=" * 60)

    # 1. DATA MATCHING YOUR CIC-IDS-2017 TRANSFORMER MODEL
    # Ensure these keys match exactly what's in your preprocessor.pkl metadata
    payload = {
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.5",
        "protocol": "TCP",
        "port": 80,
        "duration": 1293792,
        "features": {
            "Destination Port": 80, "Flow Duration": 1293792, "Total Fwd Packets": 3,
            "Total Backward Packets": 7, "Total Length of Fwd Packets": 26,
            "Total Length of Bwd Packets": 11607, "Fwd Packet Length Max": 20,
            "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 8.66,
            "Fwd Packet Length Std": 10.26, "Bwd Packet Length Max": 5840,
            "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 1658.14,
            "Bwd Packet Length Std": 2137.29, "Flow Bytes/s": 8991.39,
            "Flow Packets/s": 7.72, "Flow IAT Mean": 143754.66, "Flow IAT Std": 430865.8,
            "Flow IAT Max": 1292730, "Flow IAT Min": 2, "Fwd IAT Total": 747,
            "Fwd IAT Mean": 373.5, "Fwd IAT Std": 523.96, "Fwd IAT Max": 744,
            "Fwd IAT Min": 3, "Bwd IAT Total": 1293746, "Bwd IAT Mean": 215624.33,
            "Bwd IAT Std": 527671.93, "Bwd IAT Max": 1292730, "Bwd IAT Min": 2,
            "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0,
            "Bwd URG Flags": 0, "Fwd Header Length": 72, "Bwd Header Length": 152,
            "Fwd Packets/s": 2.31, "Bwd Packets/s": 5.41, "Min Packet Length": 0,
            "Max Packet Length": 5840, "Packet Length Mean": 1057.54,
            "Packet Length Std": 1853.43, "Packet Length Variance": 3435230.67,
            "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "PSH Flag Count": 1, "ACK Flag Count": 0, "URG Flag Count": 0,
            "CWE Flag Count": 0, "ECE Flag Count": 0, "Down/Up Ratio": 2,
            "Average Packet Size": 1163.3, "Avg Fwd Segment Size": 8.66,
            "Avg Bwd Segment Size": 1658.14, "Fwd Header Length.1": 72,
            "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": 3, "Subflow Fwd Bytes": 26, "Subflow Bwd Packets": 7,
            "Subflow Bwd Bytes": 11607, "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 229, "act_data_pkt_fwd": 2,
            "min_seg_size_forward": 20, "Active Mean": 0.0, "Active Std": 0.0,
            "Active Max": 0, "Active Min": 0, "Idle Mean": 0.0, "Idle Std": 0.0,
            "Idle Max": 0, "Idle Min": 0
        }
    }

    # ------------------------------------------------
    # PHASE 1: DETECTION (ML)
    # ------------------------------------------------
    print("\n[PHASE 1] Initiating ML Detection...")
    start_time = time.time()
    # Path is /detection/analyze based on your api.py prefix
    detection_results = send_request("detection/analyze", payload)

    if not detection_results: 
        print("❌ Detection phase failed. Aborting.")
        return

    # Check for threat based on your API return keys
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
        
        # Reasoning API expected keys (ensure apps/reasoning/api.py matches these)
        reasoning_payload = {
            "predicted_class": threat_type,
            "confidence": confidence,
            "source_ip": payload["source_ip"],
            "threat_level": "HIGH" if confidence > 0.7 else "MEDIUM"
        }
        
        start_time = time.time()
        # Path based on reasoning router
        reasoning_results = send_request("reasoning/reason", reasoning_payload)

        if not reasoning_results: return

        risk_level = reasoning_results.get('risk_level', 'MEDIUM')
        print(f"  > Risk Level   : {risk_level}")
        print(f"  > RAG Context  : Used {len(reasoning_results.get('cve_context_used', []))} CVE records")
        print(f"\n  > AI SUMMARY   :")
        print(f"    {reasoning_results.get('threat_summary', 'No summary generated.')}")
        
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
            print(f"  > Process Time : {time.time() - start_time:.2f}s")
            
    else:
        print("\nResult: BENIGN - System remains in monitoring mode.")

    print("\n" + "=" * 60)
    print("              TEST SEQUENCE COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    test_full_system_flow()