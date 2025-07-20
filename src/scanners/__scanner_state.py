# __scanner_state.py
from bs4 import BeautifulSoup as soup

class ScannerState:
    def __init__(self):
        self.url_stack = []
        self.form_stack = []
        self.cookie_stack = []
        self.header_stack = []
        
        self.visited_urls = set()

    def add_url(self, url):
        # Avoid duplicates and track visited URLs
        if url not in self.visited_urls:
            self.url_stack.append(url)
            self.visited_urls.add(url)

    def get_next_url(self):
        return self.url_stack.pop() if self.url_stack else None

    def add_form(self, form_info):
        self.form_stack.append(form_info)

    def add_cookies(self, cookies):
        self.cookie_stack.append(cookies)

    def add_headers(self, headers):
        self.header_stack.append(headers)

    def parse_target(self, target_html):
        # Need to ensure that target_html is valid
        parsed = soup(target_html.text, "html.parser")

        # Parse urls
        for url in parsed.find_all("a", href=True):
            href = url.get("href")
            url_info = {
                "href": href, 
                "text": url.text.strip()
            }
            self.add_url(href)

        # Parse forms
        for form in parsed.find_all("form"):
            form_info = {
                "action": form.get("action"),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            for input_tag in form.find_all("input"):
                input_info = {
                    "name": input_tag.get("name"),
                    "type": input_tag.get("type", "text")
                }
                form_info["inputs"].append(input_info)
            self.add_form(form_info)

        # Parse cookies
        cookies = target_html.cookies.get_dict() if hasattr(target_html, 'cookies') else {}
        if cookies:
            self.add_cookies(cookies)

        # Parse headers
        headers = dict(target_html.headers) if hasattr(target_html, 'headers') else {}
        if headers:
            self.add_headers(headers)
