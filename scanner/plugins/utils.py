import requests
from bs4 import BeautifulSoup, Comment
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


def recon(session: requests.Session, target: str):
    baseline = send_request(session, target)
    if baseline is None:
        return None
    
    baseline_fingerprint = response_fingerprint(baseline)

    result = {
        "url": target,
        "status_code": baseline_fingerprint[0],
        "content_length": baseline_fingerprint[1],
        "hash": baseline_fingerprint[2],
        "headers": dict(baseline.headers),
        "cookies": session.cookies.get_dict(),
        "security_headers": {},
        "forms": [],
        "scripts": [],
        "links": [],
        "comments": []
    }
    
    security_headers = ["Content-Security-Policy", "Strict-Transport-Security", 
                        "X-Frame-Options", "X-Content-Type-Options", 
                        "Referrer-Policy", "Permissions-Policy"]
    for h in security_headers:
        if h in baseline.headers:
            result["security_headers"][h] = baseline.headers[h]
    
    soup = BeautifulSoup(baseline.text, 'html.parser')

    for form in soup.find_all('form'):
        form_data = {
            "action": form.get('action'),
            "method": form.get('method', 'GET').upper(),
            "inputs": []
        }
        for inp in form.find_all('input'):
            form_data["inputs"].append({
                "name": inp.get('name'),
                "type": inp.get('type', 'text'),
                "value": inp.get('value', '')
            })
        result["forms"].append(form_data)
    
    result["scripts"] = [script.get('src') for script in soup.find_all('script') if script.get('src')]

    result["links"] = [a.get('href') for a in soup.find_all('a') if a.get('href')]

    result["comments"] = [c for c in soup.find_all(string=lambda text: isinstance(text, Comment))]

    return result