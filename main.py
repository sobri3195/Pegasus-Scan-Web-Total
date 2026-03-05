import argparse
from collections import Counter
import concurrent.futures
import csv
import json
import os
import requests
import socket
import ssl
import sys
import threading
import time
import hashlib
import re
from datetime import datetime
from requests.exceptions import RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from protection import CodeProtection, detect_debugging, prevent_modification

# Initialize protection
protection = CodeProtection()
detect_debugging()
prevent_modification()

# Only require activation once through the protection module
# (Remove the second activation check)
protection.start_protection()

# ASCII Art Banner
BANNER = """
██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║   ██║██╔════╝
██████╔╝█████╗  ██║     ███████║██╔██╗ ██║█████╗  ██║   ██║███████╗
██╔═══╝ ██╔══╝  ██║     ██╔══██║██║╚██╗██║██╔══╝  ╚██╗ ██╔╝╚════██║
██║     ███████╗╚██████╗██║  ██║██║ ╚████║███████╗ ╚████╔╝ ███████║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝  ╚═══╝  ╚══════╝
                                                                    
███████╗ ██████╗██████╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║     ██████╔╝██████╔╝██║     ███████╗██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██╗██╔══██╗██║     ╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                    
██╗   ██╗███████╗██████╗     ████████╗ ██████╗ ██████╗  █████╗ ██╗     
██║   ██║██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██║     
██║   ██║█████╗  ██████╔╝       ██║   ██║   ██║██████╔╝███████║██║     
╚██╗ ██╔╝██╔══╝  ██╔══██╗       ██║   ██║   ██║██╔══██╗██╔══██║██║     
 ╚████╔╝ ███████╗██║  ██║       ██║   ╚██████╔╝██║  ██║██║  ██║███████╗
  ╚═══╝  ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                    
Author: Letda Kes Dr. Sobri, S.Kom.
Contact: muhammadsobrimaulana31@gmail.com
GitHub: github.com/sobri3195
Donate: https://lynk.id/muhsobrimaulana
"""

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Print the colored banner"""
    print(Colors.CYAN + BANNER + Colors.ENDC)
    print(Colors.YELLOW + "=" * 80 + Colors.ENDC)
    print(Colors.GREEN + "Pegasus Scan Web Total - A Comprehensive Web Security Scanner" + Colors.ENDC)
    print(Colors.YELLOW + "=" * 80 + Colors.ENDC)

def activate_license():
    """Activate the license with the key 'sobri'"""
    print(Colors.CYAN + "\n[*] Checking license..." + Colors.ENDC)
    
    activation_key = input(Colors.YELLOW + "[?] Enter activation key: " + Colors.ENDC)
    
    if activation_key.lower() == "sobri":
        print(Colors.GREEN + "[+] License activated successfully!" + Colors.ENDC)
        return True
    else:
        print(Colors.RED + "[-] Invalid activation key. Please contact the author." + Colors.ENDC)
        return False

class PegasusScan:
    def __init__(self, args):
        self.url = args.url
        parsed_url = urlparse(args.url)
        self.domain = parsed_url.netloc
        self.hostname = parsed_url.hostname or self.domain
        self.timeout = args.timeout
        self.output_file = args.output
        self.output_format = args.format
        self.wordlist = args.wordlist
        self.threads = args.threads
        self.verbose = args.verbose
        self.enabled_scans = set(args.scans)
        self.results = []
        self.result_fingerprints = set()
        self.result_lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PegasusScan/1.0',
        })
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.base_url = self.url.rstrip("/")
    
    def log(self, message, level="INFO"):
        """Log messages based on verbosity level"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.verbose or level in {"ERROR", "FOUND", "WARN"}:
            color = Colors.GREEN if level == "INFO" else Colors.RED if level == "ERROR" else Colors.YELLOW
            print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}")
    
    def add_result(self, scan_type, details, severity="Medium"):
        """Add scan result to the results list"""
        fingerprint = hashlib.sha256(f"{scan_type}:{details}:{severity}".encode()).hexdigest()
        with self.result_lock:
            if fingerprint in self.result_fingerprints:
                return
            self.result_fingerprints.add(fingerprint)
            self.results.append({
                "scan_type": scan_type,
                "details": details,
                "severity": severity,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        self.log(f"{scan_type}: {details}", "FOUND")

    def _run_scan(self, key, fn):
        if key in self.enabled_scans:
            fn()

    def build_url(self, path):
        return f"{self.base_url}/{path.lstrip('/')}"
    
    def scan_vulnerabilities(self):
        """Scan for common vulnerable paths"""
        self.log("Scanning for common vulnerabilities...")
        vulnerabilities = [
            "/admin", "/login", "/config.php", "/backup.zip", 
            "/wp-admin", "/administrator", "/phpinfo.php"
        ]
        
        for vuln in vulnerabilities:
            try:
                response = self.session.get(f"{self.url}{vuln}", timeout=self.timeout)
                if response.status_code == 200:
                    self.add_result("Vulnerable Path", f"{self.url}{vuln}", "High")
            except RequestException as e:
                self.log(f"Error checking {vuln}: {str(e)}", "ERROR")

    def xss_scan(self):
        """Scan for XSS vulnerabilities"""
        self.log("Scanning for XSS vulnerabilities...")
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    self.url, 
                    params={"search": payload, "q": payload}, 
                    timeout=self.timeout
                )
                if payload in response.text:
                    self.add_result("XSS Vulnerability", f"Payload: {payload}", "High")
                    break
            except RequestException as e:
                self.log(f"Error during XSS scan: {str(e)}", "ERROR")

    def sql_injection_scan(self):
        """Scan for SQL injection vulnerabilities"""
        self.log("Scanning for SQL injection vulnerabilities...")
        payloads = [
            "' OR '1'='1", 
            "1' OR '1'='1", 
            "'; DROP TABLE users; --",
            "1' AND 1=1 --"
        ]
        
        error_patterns = [
            "sql syntax", "syntax error", "mysql_fetch", 
            "database error", "SQL syntax", "ORA-", "Error:"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.url}?id={payload}", timeout=self.timeout)
                response_text = response.text.lower()
                
                for pattern in error_patterns:
                    if pattern in response_text:
                        self.add_result("SQL Injection", f"Payload: {payload}", "Critical")
                        return
            except RequestException as e:
                self.log(f"Error during SQL injection scan: {str(e)}", "ERROR")

    def directory_brute_force(self):
        """Perform directory brute force attack"""
        if not os.path.exists(self.wordlist):
            self.log(f"Wordlist file not found: {self.wordlist}", "ERROR")
            return
            
        self.log(f"Starting directory brute force with wordlist: {self.wordlist}")
        
        try:
            with open(self.wordlist, 'r') as file:
                directories = file.read().splitlines()
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._check_directory, directory): directory for directory in directories}
                
                for future in concurrent.futures.as_completed(futures):
                    # Results are handled in the _check_directory method
                    pass
                    
        except Exception as e:
            self.log(f"Error during directory brute force: {str(e)}", "ERROR")
    
    def _check_directory(self, directory):
        """Helper method to check a single directory"""
        try:
            response = self.session.get(f"{self.url}/{directory}", timeout=self.timeout)
            if response.status_code == 200:
                self.add_result("Directory Found", f"{self.url}/{directory}", "Medium")
        except RequestException:
            pass

    def enumerate_subdomains(self):
        """Enumerate subdomains using a wordlist"""
        if not os.path.exists(self.wordlist):
            self.log(f"Wordlist file not found: {self.wordlist}", "ERROR")
            return
            
        self.log(f"Enumerating subdomains for {self.domain}...")
        
        try:
            with open(self.wordlist, 'r') as file:
                subdomains = file.read().splitlines()
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._check_subdomain, subdomain): subdomain for subdomain in subdomains}
                
                for future in concurrent.futures.as_completed(futures):
                    # Results are handled in the _check_subdomain method
                    pass
                    
        except Exception as e:
            self.log(f"Error during subdomain enumeration: {str(e)}", "ERROR")
    
    def _check_subdomain(self, subdomain):
        """Helper method to check a single subdomain"""
        url = f"http://{subdomain}.{self.domain}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                self.add_result("Subdomain", url, "Low")
        except RequestException:
            pass

    def scan_http_headers(self):
        """Scan and analyze HTTP headers"""
        self.log("Scanning HTTP headers...")
        
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header"
        }
        
        try:
            response = self.session.head(self.url, timeout=self.timeout)
            headers = response.headers
            
            # Log all headers if verbose
            if self.verbose:
                for header, value in headers.items():
                    self.log(f"Header: {header}: {value}")
            
            # Check for missing security headers
            for header, message in security_headers.items():
                if header not in headers:
                    self.add_result("Security Header", message, "Low")
                    
            # Check for information disclosure
            server = headers.get("Server", "")
            if server and not server == "":
                self.add_result("Information Disclosure", f"Server: {server}", "Low")
                
        except RequestException as e:
            self.log(f"Error scanning HTTP headers: {str(e)}", "ERROR")

    def scan_https_redirect(self):
        """Check if HTTP redirects to HTTPS"""
        if not self.url.startswith("http://"):
            return
        
        self.log("Checking HTTPS redirect...")
        try:
            response = self.session.get(self.url, timeout=self.timeout, allow_redirects=False)
            location = response.headers.get("Location", "")
            if response.status_code in [301, 302, 307, 308] and location.startswith("https://"):
                self.add_result("HTTPS Redirect", f"Redirects to {location}", "Low")
            else:
                self.add_result("HTTPS Redirect", "HTTP does not redirect to HTTPS", "Medium")
        except RequestException as e:
            self.log(f"Error checking HTTPS redirect: {str(e)}", "ERROR")

    def scan_http_methods(self):
        """Check for dangerous HTTP methods"""
        self.log("Checking allowed HTTP methods...")
        try:
            response = self.session.options(self.url, timeout=self.timeout)
            allow_header = response.headers.get("Allow", "")
            methods = {method.strip().upper() for method in allow_header.split(",") if method.strip()}
            
            if not methods:
                allow_methods = response.headers.get("Access-Control-Allow-Methods", "")
                methods = {method.strip().upper() for method in allow_methods.split(",") if method.strip()}
            
            dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
            exposed = sorted(methods.intersection(dangerous_methods))
            if exposed:
                self.add_result("HTTP Methods", f"Dangerous methods enabled: {', '.join(exposed)}", "Medium")
        except RequestException as e:
            self.log(f"Error checking HTTP methods: {str(e)}", "ERROR")

    def scan_trace_method(self):
        """Check if TRACE method is enabled"""
        self.log("Checking TRACE method...")
        try:
            response = self.session.request("TRACE", self.url, timeout=self.timeout)
            if response.status_code < 400:
                self.add_result("HTTP TRACE", "TRACE method is enabled", "Medium")
        except RequestException as e:
            self.log(f"Error checking TRACE method: {str(e)}", "ERROR")

    def _extract_set_cookie_headers(self, response):
        raw_headers = getattr(response.raw, "headers", None)
        if raw_headers:
            if hasattr(raw_headers, "get_all"):
                return raw_headers.get_all("Set-Cookie")
            if hasattr(raw_headers, "getlist"):
                return raw_headers.getlist("Set-Cookie")

        combined = response.headers.get("Set-Cookie")
        if combined:
            return [cookie.strip() for cookie in re.split(r", (?=[^;]+?=)", combined) if cookie.strip()]
        return []

    def scan_cookie_security(self):
        """Check cookies for missing security flags"""
        self.log("Checking cookie security flags...")
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            cookies = self._extract_set_cookie_headers(response)
            if not cookies:
                return
            
            for cookie in cookies:
                cookie_name = cookie.split("=", 1)[0].strip() or "(unknown)"
                lower_cookie = cookie.lower()
                
                if "secure" not in lower_cookie:
                    severity = "Medium" if self.url.startswith("https://") else "Low"
                    self.add_result("Cookie Security", f"Cookie '{cookie_name}' missing Secure flag", severity)
                if "httponly" not in lower_cookie:
                    self.add_result("Cookie Security", f"Cookie '{cookie_name}' missing HttpOnly flag", "Medium")
                if "samesite" not in lower_cookie:
                    self.add_result("Cookie Security", f"Cookie '{cookie_name}' missing SameSite flag", "Low")
        except RequestException as e:
            self.log(f"Error checking cookie security: {str(e)}", "ERROR")

    def scan_cors_policy(self):
        """Check for permissive CORS policies"""
        self.log("Checking CORS policy...")
        try:
            origin = "https://evil.example"
            response = self.session.get(self.url, headers={"Origin": origin}, timeout=self.timeout)
            allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
            allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower()
            
            if allow_origin == "*" and allow_credentials == "true":
                self.add_result("CORS Policy", "Wildcard origin allowed with credentials", "High")
            elif allow_origin == origin and allow_credentials == "true":
                self.add_result("CORS Policy", "Reflects arbitrary origin with credentials", "High")
            elif allow_origin == origin:
                self.add_result("CORS Policy", "Reflects arbitrary origin", "Medium")
        except RequestException as e:
            self.log(f"Error checking CORS policy: {str(e)}", "ERROR")

    def scan_directory_listing(self):
        """Check for directory listing exposure"""
        self.log("Checking for directory listing...")
        try:
            response = self.session.get(f"{self.base_url}/", timeout=self.timeout)
            if response.status_code == 200:
                indicators = ["Index of /", "Directory listing for", "Parent Directory"]
                if any(indicator in response.text for indicator in indicators):
                    self.add_result("Directory Listing", f"Directory listing enabled at {self.base_url}/", "Medium")
        except RequestException as e:
            self.log(f"Error checking directory listing: {str(e)}", "ERROR")

    def scan_security_txt(self):
        """Check for security.txt"""
        self.log("Checking security.txt...")
        paths = [".well-known/security.txt", "security.txt"]
        found = False
        for path in paths:
            try:
                response = self.session.get(self.build_url(path), timeout=self.timeout)
                if response.status_code == 200:
                    self.add_result("security.txt", f"Found {path}", "Low")
                    found = True
                    break
            except RequestException as e:
                self.log(f"Error checking {path}: {str(e)}", "ERROR")
        if not found:
            self.add_result("security.txt", "security.txt not found", "Low")

    def scan_sitemap(self):
        """Check for sitemap.xml"""
        self.log("Checking sitemap.xml...")
        try:
            response = self.session.get(self.build_url("sitemap.xml"), timeout=self.timeout)
            if response.status_code == 200 and ("<urlset" in response.text or "<sitemapindex" in response.text):
                url_count = len(re.findall(r"<loc>", response.text))
                detail = f"Sitemap discovered with {url_count} URLs" if url_count else "Sitemap discovered"
                self.add_result("Sitemap", detail, "Low")
        except RequestException as e:
            self.log(f"Error checking sitemap.xml: {str(e)}", "ERROR")

    def scan_open_redirect(self):
        """Check for open redirect vulnerabilities"""
        self.log("Checking for open redirects...")
        payload = "https://example.com"
        parameters = ["next", "url", "redirect", "return", "dest", "destination", "continue"]
        for parameter in parameters:
            try:
                response = self.session.get(self.url, params={parameter: payload}, timeout=self.timeout, allow_redirects=False)
                location = response.headers.get("Location", "")
                if response.status_code in [301, 302, 303, 307, 308] and payload in location:
                    self.add_result("Open Redirect", f"Parameter '{parameter}' redirects to external site", "High")
                    break
            except RequestException as e:
                self.log(f"Error checking open redirect with {parameter}: {str(e)}", "ERROR")

    def scan_backup_files(self):
        """Check for exposed backup files"""
        self.log("Checking for backup files...")
        backup_files = [
            "index.php~", "index.php.bak", "index.php.old", "index.php.save",
            "index.html~", "index.html.bak", "index.html.old", "config.php.bak",
            "config.php~", ".env.bak", ".env.old", "backup.tar.gz", "backup.zip"
        ]
        
        for file in backup_files:
            try:
                response = self.session.get(self.build_url(file), timeout=self.timeout)
                if response.status_code == 200:
                    self.add_result("Backup File", f"Found backup file: {self.build_url(file)}", "High")
            except RequestException:
                pass

    def scan_ssl_tls(self):
        """Scan SSL/TLS configuration"""
        self.log(f"Scanning SSL/TLS for {self.hostname}...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_date = ssl.cert_time_to_seconds(not_after)
                        current_time = time.time()
                        days_left = (expiry_date - current_time) / (24*60*60)
                        
                        if days_left < 30:
                            self.add_result(
                                "SSL Certificate", 
                                f"Certificate expires in {int(days_left)} days", 
                                "High" if days_left < 7 else "Medium"
                            )
                    
                    # Report cipher and protocol information
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        self.add_result("SSL/TLS", f"Insecure protocol: {protocol}", "High")
                    
                    self.log(f"SSL/TLS: Protocol: {protocol}, Cipher: {cipher}")
                    
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            self.log(f"Error scanning SSL/TLS: {str(e)}", "ERROR")
        except Exception as e:
            self.log(f"Unexpected error during SSL/TLS scan: {str(e)}", "ERROR")

    def scan_robots_txt(self):
        """Scan robots.txt file"""
        self.log("Scanning robots.txt...")
        
        try:
            response = self.session.get(f"{self.url}/robots.txt", timeout=self.timeout)
            if response.status_code == 200:
                interesting_paths = []
                lines = response.text.splitlines()
                
                for line in lines:
                    if line.startswith("Disallow:"):
                        path = line.split("Disallow:")[1].strip()
                        if path and path not in ["/", "*"]:
                            interesting_paths.append(path)
                
                if interesting_paths:
                    self.add_result(
                        "robots.txt", 
                        f"Found {len(interesting_paths)} interesting paths", 
                        "Low"
                    )
                    if self.verbose:
                        for path in interesting_paths:
                            self.log(f"Interesting path in robots.txt: {path}")
                            
        except RequestException as e:
            self.log(f"Error scanning robots.txt: {str(e)}", "ERROR")

    def scan_sensitive_files(self):
        """Scan for sensitive files"""
        self.log("Scanning for sensitive files...")
        sensitive_files = [
            "/.git/HEAD", "/.env", "/config.php", "/backup.zip", "/wp-config.php",
            "/.htaccess", "/.bash_history", "/credentials.txt", "/database.sql",
            "/.svn/entries", "/.DS_Store", "/composer.json", "/package.json"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_sensitive_file, file): file for file in sensitive_files}
            
            for future in concurrent.futures.as_completed(futures):
                # Results are handled in the _check_sensitive_file method
                pass
    
    def _check_sensitive_file(self, file):
        """Helper method to check a single sensitive file"""
        try:
            response = self.session.get(f"{self.url}{file}", timeout=self.timeout)
            if response.status_code == 200:
                self.add_result("Sensitive File", f"{self.url}{file}", "High")
        except RequestException:
            pass

    def detect_cms(self):
        """Detect Content Management System"""
        self.log("Detecting CMS...")
        cms_signatures = {
            "WordPress": ["/wp-content/", "/wp-admin/", "/wp-includes/"],
            "Joomla": ["/administrator/", "/components/", "/templates/system/"],
            "Drupal": ["/sites/default/", "/modules/", "/themes/"],
            "Magento": ["/skin/frontend/", "/app/Mage.php", "/downloader/"],
            "PrestaShop": ["/admin", "/modules/", "/controllers/"]
        }
        
        found_cms = []
        
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                try:
                    response = self.session.get(f"{self.url}{signature}", timeout=self.timeout)
                    if response.status_code == 200:
                        found_cms.append(cms)
                        self.add_result("CMS Detection", f"Detected {cms}", "Low")
                        break
                except RequestException:
                    pass
        
        if not found_cms and self.verbose:
            self.log("No CMS detected")

    def save_results(self):
        """Save scan results to a file"""
        if not self.results:
            self.log("No results to save")
            return
            
        if not self.output_file:
            return
            
        try:
            severity_summary = dict(Counter(item["severity"] for item in self.results))
            if self.output_format == "json":
                with open(self.output_file, 'w') as f:
                    json.dump({
                        "target": self.url,
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity_summary": severity_summary,
                        "results": self.results
                    }, f, indent=4)
            elif self.output_format == "csv":
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Scan Type", "Details", "Severity", "Timestamp"])
                    for result in self.results:
                        writer.writerow([
                            result["scan_type"],
                            result["details"],
                            result["severity"],
                            result["timestamp"]
                        ])
                    writer.writerow([])
                    writer.writerow(["Severity Summary"])
                    writer.writerow(["Severity", "Count"])
                    for severity, count in sorted(severity_summary.items()):
                        writer.writerow([severity, count])
            
            self.log(f"Results saved to {self.output_file}")
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")

    def run(self):
        """Run all scans"""
        start_time = time.time()
        self.log(f"Starting Pegasus Scan on {self.url}")
        
        try:
            self._run_scan("vulnerabilities", self.scan_vulnerabilities)
            self._run_scan("xss", self.xss_scan)
            self._run_scan("sqli", self.sql_injection_scan)
            self._run_scan("dir_bruteforce", self.directory_brute_force)
            self._run_scan("subdomains", self.enumerate_subdomains)
            self._run_scan("headers", self.scan_http_headers)
            self._run_scan("https_redirect", self.scan_https_redirect)
            self._run_scan("http_methods", self.scan_http_methods)
            self._run_scan("trace", self.scan_trace_method)
            self._run_scan("cookies", self.scan_cookie_security)
            self._run_scan("cors", self.scan_cors_policy)
            self._run_scan("directory_listing", self.scan_directory_listing)
            self._run_scan("security_txt", self.scan_security_txt)
            self._run_scan("sitemap", self.scan_sitemap)
            self._run_scan("open_redirect", self.scan_open_redirect)
            self._run_scan("backup_files", self.scan_backup_files)
            
            # Only run SSL/TLS scan if using HTTPS
            if self.url.startswith("https://") and "ssl_tls" in self.enabled_scans:
                self.scan_ssl_tls()
                
            self._run_scan("robots", self.scan_robots_txt)
            self._run_scan("sensitive_files", self.scan_sensitive_files)
            self._run_scan("cms", self.detect_cms)
            
            # Save the results
            self.save_results()
            
            duration = time.time() - start_time
            self.log(f"Scan completed in {duration:.2f} seconds")
            self.log(f"Found {len(self.results)} issues")
            
        except KeyboardInterrupt:
            self.log("Scan interrupted by user", "ERROR")
            self.save_results()
        except Exception as e:
            self.log(f"Unexpected error during scan: {str(e)}", "ERROR")

available_scans = [
    "vulnerabilities", "xss", "sqli", "dir_bruteforce", "subdomains", "headers",
    "https_redirect", "http_methods", "trace", "cookies", "cors", "directory_listing",
    "security_txt", "sitemap", "open_redirect", "backup_files", "ssl_tls", "robots",
    "sensitive_files", "cms"
]

def main():
    # Print banner
    print_banner()
    
    # Activation is already handled by protection module
    # No need to check again here
    
    parser = argparse.ArgumentParser(description="Pegasus Scan Web Total - A Comprehensive Web Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent operations")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--scans",
        nargs="+",
        choices=available_scans,
        default=available_scans,
        help="Specific scan modules to run (default: all modules)",
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url
        
    scanner = PegasusScan(args)
    scanner.run()

if __name__ == "__main__":
    main()
