# report.py
import json
from datetime import datetime
import uuid

class Report:
    def __init__(self, target):
        self.data = {
            "target": target,
            "date": str(datetime.utcnow()),
            "number of findings": 0,
            "findings": []
        }

    def add_finding(self, name, severity, description, evidence, recommendation, affected):
        # unique id for finding
        unique_id = str(uuid.uuid4())

        self.data["findings"].append({
            "name": name,
            "id": unique_id,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "affected": affected
        })

    def save_json(self, path):
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)
