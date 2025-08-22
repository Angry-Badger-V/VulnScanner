import requests
import hashlib

def send_request(session: requests.Session, url: str, method: str = "GET", **kwargs):
    try:
        resp = session.request(method, url, timeout=10, verify=False, **kwargs)
        return resp
    except requests.RequestException as e:
        return None


def response_fingerprint(resp):
    if resp is None:
        return None

    body_hash = hashlib.md5(resp.text.encode(errors="ignore")).hexdigest()
    return (resp.status_code, len(resp.text), body_hash)


def compare_responses(resp1, resp2):
    if resp1 is None or resp2 is None:
        return False

    fp1 = response_fingerprint(resp1)
    fp2 = response_fingerprint(resp2)

    return fp1 != fp2
