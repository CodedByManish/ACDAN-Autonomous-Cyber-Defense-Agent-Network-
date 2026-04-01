import socket
import struct
import requests
import json

# Configuration
API_URL = "http://127.0.0.1:8000/detection/analyze"

# The full list of 78 features from your metadata.json
FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def start_sniffing():
    local_ip = get_ip_address()
    print(f"🚀 ACDAN Raw Socket Sniffer active on {local_ip}...")
    
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("💥 ERROR: You must run this terminal as ADMINISTRATOR!")
        return

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            
            # IP Header is 20 bytes
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            protocol_type = iph[6] 
            
            proto_name = "TCP" if protocol_type == 6 else "UDP" if protocol_type == 17 else "Other"
            
            port = 0
            if protocol_type in [6, 17]:
                # Port is in the first 2 bytes of the transport header (after 20 byte IP header)
                port = struct.unpack('!H', raw_data[20:22])[0]

            print(f"🔍 Captured: {src_ip} -> {dst_ip} ({proto_name}:{port})")

            # --- PREPARE 78 FEATURES ---
            # Start with all zeros
            features_dict = {name: 0.0 for name in FEATURE_NAMES}
            
            # Inject what we know from the single packet
            features_dict["Destination Port"] = float(port)
            features_dict["Total Length of Fwd Packets"] = float(len(raw_data))
            features_dict["Fwd Packet Length Max"] = float(len(raw_data))
            features_dict["Total Fwd Packets"] = 1.0
            features_dict["Flow Duration"] = 1.0 # Minimal duration for single packet
            features_dict["min_seg_size_forward"] = 20.0 # Standard IP header size

            payload = {
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": proto_name,
                "port": port,
                "features": features_dict
            }

            # Send to ACDAN Brain
            try:
                # Short timeout to keep sniffing fast
                response = requests.post(API_URL, json=payload, timeout=0.1)
                if response.status_code == 200:
                    data = response.json()
                    # Check if the model predicted a threat class other than 'BENIGN'
                    prediction = data.get("prediction", "BENIGN")
                    if prediction != "BENIGN":
                        print(f"🚨 ALERT: {prediction} Detected from {src_ip}!")
                else:
                    print(f"⚠️ API Error {response.status_code}: {response.text}")
            except Exception:
                pass

    except KeyboardInterrupt:
        print("\n🛑 Stopping Sniffer...")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    start_sniffing()