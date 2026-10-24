import json
from datetime import datetime
import os

LOG_FILE = "logs/attacks.json"

os.makedirs("logs", exist_ok=True)

def log_event(service, event_type, ip, data=None):
    entry = {
        "time": datetime.utcnow().isoformat(),
        "service": service,
        "event": event_type,
        "ip": ip,
        "data": data or {}
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

