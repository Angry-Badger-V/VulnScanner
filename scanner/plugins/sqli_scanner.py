from scanner.plugins.base import BasePlugin
from scanner.utils import send_request, compare_responses

class Plugin():

    name = "SQL Injection"
    description= "Detects SQLi vulnerabilities."
    self.payloads = ["'", "' OR 1=1--", "\" OR \"1\"=\"1"]

    def run(self, target, session):
        findings = []
        baseline = send_request(session, target)

        for payload in self.payloads:
            test_url = f"{target}?id={payload}"
            resp = send_request(session, test_url)
            if compare_responses(baseline, resp):
                findings.append({"url": test_url, "payload": payload})
        
        return findings