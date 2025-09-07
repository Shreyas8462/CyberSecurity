import requests
import re
from bs4 import BeautifulSoup
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading
import sys
import os

from flask import Flask, request, render_template_string

# --- WebSecurityScanner Class ---

class WebSecurityScanner:
    def __init__(self, target_url, max_depth=3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()

    def normalize_url(self, url):
        parsed = urllib.parse.urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
        return normalized

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.target_url

        if depth > self.max_depth:
            return

        normalized_url = self.normalize_url(url)
        if normalized_url in self.visited_urls:
            return

        print(f"Crawling: {normalized_url}")
        self.visited_urls.add(normalized_url)

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, "html.parser")
            for link_tag in soup.find_all("a", href=True):
                link = urllib.parse.urljoin(url, link_tag['href'])
                parsed_link = urllib.parse.urlparse(link)
                # Stay within the same domain
                if parsed_link.netloc == urllib.parse.urlparse(self.target_url).netloc:
                    self.crawl(link, depth + 1)

        except requests.RequestException as e:
            print(f"Request failed: {e}")

    def inject_payload(self, url, payload):
        parsed = list(urllib.parse.urlparse(url))
        query = urllib.parse.parse_qs(parsed[4])
        if query:
            for key in query:
                query[key] = payload
            parsed[4] = urllib.parse.urlencode(query, doseq=True)
            return urllib.parse.urlunparse(parsed)
        else:
            # If no query parameters, just append the payload as a query param 'test'
            return url + "?test=" + urllib.parse.quote(payload)

    def test_sql_injection(self, url):
        sql_payloads = ["' OR '1'='1", "' OR 1=1 --", "'; DROP TABLE users; --"]
        vulnerable = False
        for payload in sql_payloads:
            test_url = self.inject_payload(url, payload)
            try:
                response = self.session.get(test_url, timeout=5)
                error_patterns = [
                    r"SQL syntax.*MySQL",
                    r"Warning.*mysql_",
                    r"unclosed quotation mark after the character string",
                    r"quoted string not properly terminated",
                ]
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append((test_url, "SQL Injection"))
                        print(f"Potential SQL Injection found at {test_url}")
                        vulnerable = True
                        break
            except requests.RequestException:
                continue
        return vulnerable

    def test_xss(self, url):
        xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
        vulnerable = False
        for payload in xss_payloads:
            test_url = self.inject_payload(url, payload)
            try:
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    self.vulnerabilities.append((test_url, "XSS"))
                    print(f"Potential XSS found at {test_url}")
                    vulnerable = True
            except requests.RequestException:
                continue
        return vulnerable

    def test_directory_traversal(self, url):
        traversal_payloads = ["../", "..\\", "%2e%2e%2f", "%2e%2e\\"] 
        vulnerable = False
        for payload in traversal_payloads:
            test_url = self.inject_payload(url, payload)
            try:
                response = self.session.get(test_url, timeout=5)
                # Look for typical sensitive files in response (like /etc/passwd)
                if "root:x:0:0:" in response.text or "boot.ini" in response.text:
                    self.vulnerabilities.append((test_url, "Directory Traversal"))
                    print(f"Potential Directory Traversal found at {test_url}")
                    vulnerable = True
            except requests.RequestException:
                continue
        return vulnerable

    def report_vulnerability(self, url, vuln_type):
        print(f"[!] Vulnerability found: {vuln_type} at {url}")
        self.vulnerabilities.append((url, vuln_type))

    def scan_url(self, url):
        # Run all checks for a single URL
        if self.test_sql_injection(url):
            self.report_vulnerability(url, "SQL Injection")
        if self.test_xss(url):
            self.report_vulnerability(url, "Cross-Site Scripting (XSS)")
        if self.test_directory_traversal(url):
            self.report_vulnerability(url, "Directory Traversal")

    def scan(self):
        # Crawl to gather URLs first
        print("Starting crawl...")
        self.crawl()

        print(f"Crawling complete. {len(self.visited_urls)} URLs found.")
        print("Starting vulnerability scan...")

        # Use ThreadPoolExecutor to speed up scanning multiple URLs
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.scan_url, url) for url in self.visited_urls]
            for future in futures:
                future.result()  # Wait for all to complete

        print("Scan complete!")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        return self.vulnerabilities

    def generate_html_report(self, filename="scan_report.html"):
        html_content = "<html><head><title>Vulnerability Scan Report</title></head><body>"
        html_content += "<h1>Scan Report</h1>"
        html_content += f"<p>Total URLs scanned: {len(self.visited_urls)}</p>"
        html_content += f"<p>Total vulnerabilities found: {len(self.vulnerabilities)}</p>"
        if self.vulnerabilities:
            html_content += "<table border='1'><tr><th>URL</th><th>Vulnerability</th></tr>"
            for url, vuln in self.vulnerabilities:
                html_content += f"<tr><td>{url}</td><td>{vuln}</td></tr>"
            html_content += "</table>"
        else:
            html_content += "<p>No vulnerabilities found.</p>"
        html_content += "</body></html>"

        with open(filename, "w") as file:
            file.write(html_content)
        print(f"HTML report generated: {os.path.abspath(filename)}")


# --- Flask Web Interface ---

app = Flask(__name__)
scanner = None
scan_results = []
scanning = False

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scanner</title>
</head>
<body>
    <h1>Web Vulnerability Scanner</h1>
    <form method="post" action="/">
        <label for="url">Target URL:</label>
        <input type="text" id="url" name="url" required>
        <input type="submit" value="Start Scan">
    </form>
    {% if scanning %}
        <p>Scan in progress... Please wait.</p>
    {% endif %}
    {% if results %}
        <h2>Scan Results:</h2>
        <ul>
        {% for url, vuln in results %}
            <li><strong>{{ vuln }}</strong> found at <a href="{{ url }}" target="_blank">{{ url }}</a></li>
        {% endfor %}
        </ul>
    {% endif %}
</body>
</html>
"""

def run_scan(target_url):
    global scanner, scan_results, scanning
    scanner = WebSecurityScanner(target_url)
    scan_results = scanner.scan()
    scanning = False

@app.route("/", methods=["GET", "POST"])
def index():
    global scanning, scan_results
    if request.method == "POST":
        if not scanning:
            target_url = request.form["url"]
            scan_results = []
            scanning = True
            thread = threading.Thread(target=run_scan, args=(target_url,))
            thread.start()
    return render_template_string(HTML_TEMPLATE, scanning=scanning, results=scan_results)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        app.run(debug=True)
    elif len(sys.argv) == 2:
        target_url = sys.argv
        scanner = WebSecurityScanner(target_url)
        vulnerabilities = scanner.scan()
        print("\nScan Summary:")
        print(f"Total URLs scanned: {len(scanner.visited_urls)}")
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
        for url, vuln_type in vulnerabilities:
            print(f"- {vuln_type} detected at {url}")
    else:
        print("Usage:")
        print("  Run Flask web server: python scanner.py")
        print("  Run CLI scan: python scanner.py <target_url>")
        sys.exit(1)

# --- Main Program Entry Point ---

if __name__ == "__main__":
    # If running Flask app:
    if len(sys.argv) == 1:
        app.run(debug=True)
    # If running command line scanner with target URL:
    elif len(sys.argv) == 2:
        target_url = sys.argv[1]
        scanner = WebSecurityScanner(target_url)
        vulnerabilities = scanner.scan()

        print("\nScan Summary:")
        print(f"Total URLs scanned: {len(scanner.visited_urls)}")
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
        for url, vuln_type in vulnerabilities:
            print(f"- {vuln_type} detected at {url}")
    else:
        print("Usage:")
        print("  Run Flask web server: python scanner.py")
        print("  Run CLI scan: python scanner.py <target_url>")
        sys.exit(1)