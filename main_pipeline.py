# main_pipeline.py
import os
from apps.detection.ml_logic.inference import AnomalyDetectionInference
from apps.reasoning.rag_logic.threat_analyzer import LLMThreatAnalyzer

def run_acdan_demo():
    # 1. Initialize Detection (Phase 2)
    # Ensure you have your .pt and .pkl files in ./data/models/
    detector = AnomalyDetectionInference(models_path="./data/models")
    
    # 2. Initialize Reasoning (Phase 3)
    # Ensure Ollama is running 'mistral'
    analyzer = LLMThreatAnalyzer(llm_type="ollama", model_name="mistral")

    # 3. Simulate a Network Packet (Incoming Data)
    sample_packet = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 500,
        "dst_bytes": 0,
        # ... add other features your preprocessor expects
    }

    print("--- [PHASE 2] Detecting Anomaly ---")
    prediction = detector.predict_single(sample_packet)
    print(f"Detection Result: {prediction['predicted_class']} ({prediction['confidence']:.2%})")

    # 4. Trigger LLM Analysis if it's not 'normal'
    if prediction['threat_level'] != 'LOW':
        print("\n--- [PHASE 3] LLM Reasoning & Analysis ---")
        analysis = analyzer.analyze_threat(
            attack_type=prediction['predicted_class'],
            confidence=prediction['confidence'],
            source_ip="192.168.1.105", # Mock data
            dest_ip="10.0.0.5",
            protocol="TCP",
            port=80
        )
        print(f"LLM Summary: {analysis.get('threat_summary')}")
        print(f"Recommended Action: {analysis.get('immediate_actions')}")

if __name__ == "__main__":
    run_acdan_demo()