# sqli-scan.py
import requests
from bs4 import BeautifulSoup as soup
from __scanner_state import ScannerState

name = "sqli-scan"
description = "Detects SQLI attacks on target"

def parse_target(target_html, state):
    parsed = soup(target_html.text, "html.parser")

    # Extract all elements that might contain SQLI vulnerabilities
    for url in parsed.find_all("a", href=True):
        url_info = {
            "href": url.get("href"), 
            "text": url.text.strip()
        }
        state.add_url(url)

    #
    # Do same for forms, cookies, headers
    #

def run(target, report):
    state = ScannerState()

    target_html = requests.get(target, state)




