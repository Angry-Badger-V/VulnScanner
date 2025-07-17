# sqli-scan.py
import requests
from bs4 import BeautifulSoup as soup

name = "sqli-scan"
description = "Detects SQLI attacks on target"

def parse_target(target_html):
    urls = []
    forms = []
    cookies = []
    headers = []

    # use soup to get all of above

    return urls, forms, cookies, headers

def run(target, report):
    target_html = requests.get(target)

    urls, forms, cookies, headers = parse_target(target_html)


