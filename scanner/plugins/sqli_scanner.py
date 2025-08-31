from .base import BasePlugin
from .utils import send_request, compare_responses


class Plugin(BasePlugin):

    name = "SQL Injection"
    description= "Detects SQLi vulnerabilities."

    def run(self, target, session, reconnaissance):
        # recon
        # 
        
        payloads = ["'", "' OR 1=1--", "\" OR \"1\"=\"1"]
        findings = []
        baseline = send_request(session, target)
        print(baseline.text)

        for payload in payloads:
            test_url = f"{target}?id={payload}"
            resp = send_request(session, test_url)
            if compare_responses(baseline, resp):
                findings.append({"url": test_url, "payload": payload})
                print()
                print(resp.text)



        return findings