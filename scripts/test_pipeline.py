import requests
import json

# Configuration
BASE_URL = "http://127.0.0.1:8000/api"
TIMEOUT = 30 

def send_request(endpoint: str, payload: dict) -> dict:
    # REMOVED the trailing slash from the endpoint to match @router.post("/analyze")
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"CRITICAL: Request to {url} failed.")
        if response := getattr(exc, 'response', None):
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
        return {}

def test_full_system_flow():
    print("-" * 50)
    print("ACDAN SYSTEM INTEGRATION TEST")
    print("-" * 50)

    # 1. FULL PACKET DATA (Matching your 79-feature model)
    # We send top-level info + the nested 'features' dict
    payload = {
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.5",
        "protocol": "TCP",
        "port": 80,
        "duration": 1293792,
        "features": {
            "Destination Port": 80,
            "Flow Duration": 1293792,
            "Total Fwd Packets": 3,
            "Total Backward Packets": 7,
            "Total Length of Fwd Packets": 26,
            "Total Length of Bwd Packets": 11607,
            "Fwd Packet Length Max": 8.6,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 8.6,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 1658,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 1658,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": 8991.3,
            "Flow Packets/s": 7.7,
            "Flow IAT Mean": 215632,
            "Flow IAT Std": 534,
            "Flow IAT Max": 1293,
            "Flow IAT Min": 3,
            "Fwd IAT Total": 1293,
            "Fwd IAT Mean": 646,
            "Fwd IAT Std": 0,
            "Fwd IAT Max": 1293,
            "Fwd IAT Min": 3,
            "Bwd IAT Total": 1100,
            "Bwd IAT Mean": 180,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 500,
            "Bwd IAT Min": 5,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "Fwd Header Length": 72,
            "Bwd Header Length": 152,
            "Fwd Packets/s": 2.3,
            "Bwd Packets/s": 5.4,
            "Min Packet Length": 0,
            "Max Packet Length": 1658,
            "Packet Length Mean": 1163,
            "Packet Length Std": 500,
            "Packet Length Variance": 2500,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 2,
            "Average Packet Size": 1100,
            "Avg Fwd Segment Size": 8.6,
            "Avg Bwd Segment Size": 1658,
            "Fwd Header Length.1": 72,
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": 3,
            "Subflow Fwd Bytes": 26,
            "Subflow Bwd Packets": 7,
            "Subflow Bwd Bytes": 11607,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 255,
            "act_data_pkt_fwd": 1,
            "min_seg_size_forward": 20,
            "Active Mean": 0,
            "Active Std": 0,
            "Active Max": 0,
            "Active Min": 0,
            "Idle Mean": 0,
            "Idle Std": 0,
            "Idle Max": 0,
            "Idle Min": 0
        }
    }

    # ------------------------------------------------
    # PHASE 1: DETECTION
    # ------------------------------------------------
    print("\n[PHASE 2] Initiating ML Detection...")
    
    detection_results = send_request("detection/analyze", payload)

    if not detection_results:
        print("FAILURE: Could not connect to Detection API.")
        return

    is_threat = detection_results.get("is_threat", False)
    threat_type = detection_results.get("threat_type", "Unknown")
    confidence = detection_results.get("confidence_score", 0.0)

    print(f"Is Threat   : {is_threat}")
    print(f"Type        : {threat_type}")
    print(f"Confidence  : {confidence:.4f}")

    if is_threat:
        print("\n[PHASE 2 & 3] Would trigger Reasoning and Response...")
    else:
        print("\nResult: BENIGN - No further action required.")

    print("\n" + "-" * 50)
    print("TEST SEQUENCE COMPLETED")
    print("-" * 50)

if __name__ == "__main__":
    test_full_system_flow()