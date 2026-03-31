import json
from datetime import datetime
from pathlib import Path

def log_incident(threat_type, risk_level, action):
    log_file = Path("data/logs/incident_history.json")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "threat": threat_type,
        "risk": risk_level,
        "mitigation_action": action
    }
    
    # Append to JSON list
    data = []
    if log_file.exists():
        with open(log_file, "r") as f:
            data = json.load(f)
            
    data.append(entry)
    with open(log_file, "w") as f:
        json.dump(data, f, indent=4)