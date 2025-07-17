# __scanner_state.py

class ScannerState:
    def __init__(self):
        self.url_stack = []
        self.form_stack = []
        self.cookie_stack = []
        self.header_stack = []
        
        self.visited_urls = set()

    def add_url(self, url):
        if url not in self.visited_urls:
            self.url_stack.append(url)

    def get_next_url(self):
        return self.url_stack.pop() if self.url_stack else None