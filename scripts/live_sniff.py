from scapy.all import sniff, IP, TCP, UDP
import requests

# Your FastAPI endpoint
API_URL = "http://127.0.0.1:8000/detection/analyze"

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        
        # Get the port if it's TCP or UDP
        port = 0
        if TCP in packet: port = packet[TCP].dport
        elif UDP in packet: port = packet[UDP].dport

        print(f"🔍 Sniffed: {src_ip} -> {dst_ip} ({proto}:{port})")

        # Create a real-world payload based on ACTUAL traffic
        # We use your existing feature structure but inject real IP/Port data
        payload = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": proto,
            "port": port,
            "features": {
                "Destination Port": port,
                "Flow Duration": 1000, # Simplified
                "Total Fwd Packets": 1,
                "Total Backward Packets": 1,
                "Total Length of Fwd Packets": len(packet),
                "Total Length of Bwd Packets": 0,
                # ... other features can stay as default/low values for now
                "Init_Win_bytes_forward": 8192,
                "act_data_pkt_fwd": 1,
                "min_seg_size_forward": 20
            }
        }

        try:
            # Send the real-time packet info to your AI
            response = requests.post(API_URL, json=payload, timeout=2)
            result = response.json()
            if result.get("is_threat"):
                print(f"🚨 ALERT: Real threat detected from {src_ip}!")
        except Exception as e:
            pass

print("🚀 ACDAN Live Sniffer active... (Press Ctrl+C to stop)")
# This starts listening to your network
sniff(prn=analyze_packet, store=0, count=20)