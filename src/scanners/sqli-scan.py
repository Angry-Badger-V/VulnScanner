# sqli-scan.py
import requests
from bs4 import BeautifulSoup as soup
from __scaner_state import ScannerState

name = "sqli-scan"
description = "Detects SQLI attacks on target"

def parse_target(target_html):
    pass

def run(target, report):
    state = ScannerState()

    target_html = requests.get(target)



