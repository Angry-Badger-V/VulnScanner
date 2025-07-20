# sqli-scan.py
import requests
from __scanner_state import ScannerState

name = "sqli-scan"
description = "Detects SQLI attacks on target"


def run(target, report):
    state = ScannerState()

    target_html = requests.get(target, state)
    state.parse_target(target_html)




