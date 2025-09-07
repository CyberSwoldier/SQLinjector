import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from collections import deque
from io import BytesIO

# Try importing reportlab for PDF export
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ModuleNotFoundError:
    REPORTLAB_AVAILABLE = False


# -------------------------------
# Scanner Class
# -------------------------------
class SQLiScanner:
    def __init__(self, target_url, timeout=10, max_pages=20, debug=True):
        self.target_url = target_url
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.vulnerable = False
        self.findings = []
        self.logs = []
        self.debug = debug
        self.visited = set()
        self.queue = deque()

        self.boolean_payloads = ["' OR '1'='1' -- ", "' AND '1'='2' -- "]
        self.time_payload = "' OR SLEEP(5)--"
        self.error_payload = "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--"

    def log_debug(self, msg):
        if self.debug:
            self.logs.append(f"[DEBUG] {msg}")

    def normalize_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, progress=None):
        """Crawl for deep scan"""
        self.queue.append(self.target_url)
        self.visited.add(self.normalize_url(self.target_url))
        crawled = 0

        while self.queue and len(self.visited) < self.max_pages:
            current = self.queue.popleft()
            crawled += 1
            if progress:
                progress.progress(min(crawled / self.max_pages, 1.0))

            try:
                resp = self.session.get(current, timeout=self.timeout)
                soup = BeautifulSoup(resp.text, "html.parser")

                for link in soup.find_all("a", href=True):
                    url = urljoin(current, link["href"])
                    norm = self.normalize_url(url)
                    if norm not in self.visited and urlparse(url).netloc == urlparse(self.target_url).netloc:
                        self.visited.add(norm)
                        self.queue.append(url)
                        self.log_debug(f"Discovered: {url}")
            except Exception as e:
                self.log_debug(f"Crawl error at {current}: {e}")

    def scrape_inputs(self, url):
        inputs = []
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        if params:
            inputs.append({"action": url, "method": "get", "inputs": params})

        try:
            resp = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = form.get("method", "get").lower()
                fields = [f.get("name") for f in form.find_all("input") if f.get("name")]
                if fields:
                    inputs.append({"action": urljoin(url, action), "method": method, "inputs": fields})
        except Exception as e:
            self.log_debug(f"Form scrape error at {url}: {e}")

        return inputs

    def test_input(self, input_dict):
        action = input_dict["action"]
        method = input_dict["method"]

        for field in input_dict["inputs"]:
            # Boolean-based
            try:
                true_data = {field: self.boolean_payloads[0]}
                false_data = {field: self.boolean_payloads[1]}
                if method == "get":
                    resp_true = self.session.get(action, params=true_data, timeout=self.timeout)
                    resp_false = self.session.get(action, params=false_data, timeout=self.timeout)
                else:
                    resp_true = self.session.post(action, data=true_data, timeout=self.timeout)
                    resp_false = self.session.post(action, data=false_data, timeout=self.timeout)

                dom_diff = len(resp_true.text) != len(resp_false.text)
                if dom_diff:
                    self.vulnerable = True
                    self.findings.append({
                        "input": field,
                        "type": "Boolean-based",
                        "payload": self.boolean_payloads[0],
                        "proof": "Page response differs between payloads",
                        "url": self.build_url(action, field, self.boolean_payloads[0], method)
                    })
            except Exception as e:
                self.log_debug(f"Boolean error for {field}: {e}")

            # Time-based
            try:
                start = time.time()
                if method == "get":
                    self.session.get(action, params={field: self.time_payload}, timeout=self.timeout)
                else:
                    self.session.post(action, data={field: self.time_payload}, timeout=self.timeout)
                elapsed = time.time() - start
                if elapsed >= 5:
                    self.vulnerable = True
                    self.findings.append({
                        "input": field,
                        "type": "Time-based",
                        "payload": self.time_payload,
                        "proof": f"Response delayed {elapsed:.1f}s",
                        "url": self.build_url(action, field, self.time_payload, method)
                    })
            except Exception as e:
                self.log_debug(f"Time error for {field}: {e}")

            # Error-based
            try:
                if method == "get":
                    resp = self.session.get(action, params={field: self.error_payload}, timeout=self.timeout)
                else:
                    resp = self.session.post(action, data={field: self.error_payload}, timeout=self.timeout)

                keywords = ["sql", "syntax", "mysql", "odbc", "ora-", "conversion failed"]
                if any(k in resp.text.lower() for k in keywords):
                    self.vulnerable = True
                    self.findings.append({
                        "input": field,
                        "type": "Error-based",
                        "payload": self.error_payload,
                        "proof": "Database error in response",
                        "url": self.build_url(action, field, self.error_payload, method)
                    })
            except Exception as e:
                self.log_debug(f"Error-based error for {field}: {e}")

    def build_url(self, action, field, payload, method):
        if method == "get":
            parsed = urlparse(action)
            query = parse_qs(parsed.query)
            query[field] = payload
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query, doseq=True)}"
        else:
            return f"POST {action} with {field}={payload}"

    def scan_light(self):
        """Only test the target URL"""
        inputs = self.scrape_inputs(self.target_url)
        for inp in inputs:
            self.test_input(inp)

    def scan_deep(self, progress=None):
        self.crawl(progress)
        for url in self.visited:
            inputs = self.scrape_inputs(url)
            for inp in inputs:
                self.test_input(inp)


# -------------------------------
# PDF Export
# -------------------------------
def generate_pdf_report(target, findings, logs):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("SQL Injection Scan Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Target: {target}", styles["Normal"]))
    story.append(Spacer(1, 12))

    if findings:
        story.append(Paragraph("Vulnerabilities:", styles["Heading2"]))
        for f in findings:
            story.append(Paragraph(f"Input: {f['input']}", styles["Normal"]))
            story.append(Paragraph(f"Type: {f['type']}", styles["Normal"]))
            story.append(Paragraph(f"Payload: {f['payload']}", styles["Normal"]))
            story.append(Paragraph(f"Proof: {f['proof']}", styles["Normal"]))
            story.append(Paragraph(f"Example: {f['url']}", styles["Normal"]))
            story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("No vulnerabilities found.", styles["Normal"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Debug Logs:", styles["Heading2"]))
    for log in logs:
        story.append(Paragraph(log, styles["Code"]))

    doc.build(story)
    buffer.seek(0)
    return buffer


# -------------------------------
# Streamlit UI
# -------------------------------
def main():
    st.set_page_config(page_title="Cybersecurity SQLi Scanner", layout="centered")

    st.title("🛡️ Cybersecurity SQL Injection Scanner")
    st.caption("Scan your web applications for potential SQL Injection vulnerabilities")

    tabs = st.tabs(["⚡ Light Scan", "🔍 Deep Scan"])

    # ---------------- Light Scan ----------------
    with tabs[0]:
        st.subheader("⚡ Light Scan")
        protocol = st.selectbox("Protocol", ["https://", "http://"], index=0, key="light_protocol")
        target = st.text_input("Target", "www.example.com", key="light_target")
        agree = st.checkbox("I am authorized to scan this target and agree to the Terms of Service.", key="light_agree")
        st.markdown("[Read the Terms of Service](#)", unsafe_allow_html=True)

        if st.button("🚀 Start Light Scan", use_container_width=True, type="primary", key="light_btn"):
            if not agree:
                st.error("⚠️ Please confirm authorization before scanning.")
            else:
                url = protocol + target.strip()
                st.info(f"Starting Light Scan on `{url}`...")
                scanner = SQLiScanner(url)
                try:
                    scanner.scan_light()
                except Exception as e:
                    st.error(f"🚨 Scan failed: {e}")
                    return

                if scanner.vulnerable:
                    st.success(f"✅ Found {len(scanner.findings)} vulnerabilities")
                    for res in scanner.findings:
                        with st.expander(f"{res['type']} | {res['input']}"):
                            st.markdown(
                                f"**Input:** `{res['input']}`  \n"
                                f"**Type:** {res['type']}  \n"
                                f"**Payload:** `{res['payload']}`  \n"
                                f"**Proof:** {res['proof']}  \n"
                                f"**Example:** {res['url']}"
                            )
                else:
                    st.success("🎉 No vulnerabilities detected on this page.")

    # ---------------- Deep Scan ----------------
    with tabs[1]:
        st.subheader("🔍 Deep Scan")
        protocol = st.selectbox("Protocol", ["https://", "http://"], index=0, key="deep_protocol")
        target = st.text_input("Target", "www.example.com", key="deep_target")
        timeout = st.slider("Request Timeout (s)", 5, 30, 10, key="deep_timeout")
        max_pages = st.slider("Max Pages to Crawl", 5, 50, 15, key="deep_pages")
        debug = st.checkbox("Enable Debug Logs", True, key="deep_debug")
        agree = st.checkbox("I am authorized to scan this target and agree to the Terms of Service.", key="deep_agree")
        st.markdown("[Read the Terms of Service](#)", unsafe_allow_html=True)

        if st.button("🚀 Start Deep Scan", use_container_width=True, type="primary", key="deep_btn"):
            if not agree:
                st.error("⚠️ Please confirm authorization before scanning.")
            else:
                url = protocol + target.strip()
                st.info(f"Starting Deep Scan on `{url}`...")
                scanner = SQLiScanner(url, timeout=timeout, max_pages=max_pages, debug=debug)
                progress = st.progress(0)

                try:
                    scanner.scan_deep(progress)
                except Exception as e:
                    st.error(f"🚨 Scan failed: {e}")
                    return

                if scanner.vulnerable:
                    st.success(f"✅ Found {len(scanner.findings)} vulnerabilities")
                    for res in scanner.findings:
                        with st.expander(f"{res['type']} | {res['input']}"):
                            st.markdown(
                                f"**Input:** `{res['input']}`  \n"
                                f"**Type:** {res['type']}  \n"
                                f"**Payload:** `{res['payload']}`  \n"
                                f"**Proof:** {res['proof']}  \n"
                                f"**Example:** {res['url']}"
                            )
                else:
                    st.success("🎉 No vulnerabilities detected on the scanned pages.")

                if debug:
                    with st.expander("📜 Debug Logs"):
                        for log in scanner.logs:
                            st.code(log)

                if REPORTLAB_AVAILABLE:
                    pdf = generate_pdf_report(url, scanner.findings, scanner.logs)
                    st.download_button("📄 Download PDF Report", pdf, "sqli_report.pdf", "application/pdf", use_container_width=True)
                else:
                    st.warning("⚠️ PDF export requires `reportlab`. Install with: `pip install reportlab`")


if __name__ == "__main__":
    main()
