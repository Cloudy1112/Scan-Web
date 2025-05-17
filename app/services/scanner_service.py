# app/services/scanner_service.py
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import time
from collections import deque
import concurrent.futures

# --- Hằng số (giữ nguyên từ phiên bản trước) ---
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"SQL command not properly ended", r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server", r"System.Data.SqlClient.SqlException",
    r"mssql", r"syntax error near", r"Incorrect syntax near", r"MariaDB", r"PostgreSQL",
    r"Unknown column .* in 'where clause'", r"Division by zero",
    r"supplied argument is not a valid .* result resource", r"Call to a member function .* on boolean",
    r"pg_query\(\): Query failed:", r"XPath error",
]
SQLI_TIME_BASED_KEYWORDS = ["SLEEP", "BENCHMARK", "pg_sleep", "WAITFOR DELAY"]
SQLI_TIME_DELAY_SENSITIVITY = 0.8
SQLI_CWE_ID = "CWE-89"
SQLI_OWASP_CATEGORY = "A03:2021-Injection"
SQLI_ERROR_NAME = "SQL Injection"

XSS_CWE_ID = "CWE-79"
XSS_OWASP_CATEGORY = "A03:2021-Injection"
XSS_ERROR_NAME_REFLECTED = "Reflected Cross-Site Scripting (XSS)"

# --- Các hàm kiểm tra lỗi (giữ nguyên từ phiên bản trước) ---
def is_sqli_time_based_payload(payload_str):
    return any(keyword.lower() in payload_str.lower() for keyword in SQLI_TIME_BASED_KEYWORDS)

def extract_sqli_sleep_duration(payload_str):
    match = re.search(r"\b(?:SLEEP|pg_sleep)\s*\(\s*(\d+)\s*\)", payload_str, re.IGNORECASE)
    if match: return int(match.group(1))
    match = re.search(r"\bBENCHMARK\s*\(\s*(\d+)\s*,", payload_str, re.IGNORECASE)
    if match:
        duration_indicator = int(match.group(1));
        if duration_indicator >= 5000000: return 5
        if duration_indicator >= 2000000: return 2
        return 1
    match = re.search(r"\bWAITFOR DELAY\s*'[^']*?(\d{1,2}):(\d{1,2}):(\d{1,2})[^']*?'", payload_str, re.IGNORECASE)
    if match:
        hours, minutes, seconds = map(int, match.groups()); return hours * 3600 + minutes * 60 + seconds
    return 5

def check_for_sqli(response_text, response_time, baseline_response_time, payload_str):
    for pattern in SQLI_ERROR_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True, "Error-based", f"Phát hiện mẫu lỗi SQL: '{pattern}'", SQLI_ERROR_NAME, SQLI_CWE_ID, SQLI_OWASP_CATEGORY
    if is_sqli_time_based_payload(payload_str):
        expected_delay = extract_sqli_sleep_duration(payload_str)
        actual_payload_delay = response_time - baseline_response_time
        if expected_delay > 1 and actual_payload_delay >= expected_delay * SQLI_TIME_DELAY_SENSITIVITY:
             return True, "Time-based", f"Phản hồi SQLi bị trễ {actual_payload_delay:.2f}s (dự kiến {expected_delay}s, baseline: {baseline_response_time:.2f}s)", SQLI_ERROR_NAME, SQLI_CWE_ID, SQLI_OWASP_CATEGORY
        elif baseline_response_time < 1 and response_time >= expected_delay * SQLI_TIME_DELAY_SENSITIVITY and expected_delay > 1:
             return True, "Time-based", f"Phản hồi SQLi bị trễ {response_time:.2f}s (dự kiến {expected_delay}s, baseline nhanh)", SQLI_ERROR_NAME, SQLI_CWE_ID, SQLI_OWASP_CATEGORY
    return False, None, None, None, None, None

def check_for_xss(response_text, injected_payload):
    testable_part = injected_payload 
    script_match = re.search(r"<script.*?>.*?</script>", injected_payload, re.IGNORECASE | re.DOTALL)
    svg_match = re.search(r"<svg.*?>.*?</svg>", injected_payload, re.IGNORECASE | re.DOTALL)
    img_onerror_match = re.search(r"<img[^>]+onerror\s*=", injected_payload, re.IGNORECASE)
    generic_event_handler_match = re.search(r"on[a-zA-Z]+\s*=", injected_payload, re.IGNORECASE)
    if script_match: testable_part = script_match.group(0)
    elif svg_match: testable_part = svg_match.group(0)
    elif img_onerror_match: testable_part = img_onerror_match.group(0) 
    elif generic_event_handler_match:
        match_full_handler = re.search(r"(on[a-zA-Z]+\s*=\s*[^>]+)", injected_payload, re.IGNORECASE)
        if match_full_handler: testable_part = match_full_handler.group(1)
    if testable_part in response_text:
        for match_obj in re.finditer(re.escape(testable_part), response_text, re.IGNORECASE | re.DOTALL):
            pos = match_obj.start()
            context_before = response_text[max(0, pos - 10) : pos]
            if not re.search(r"&(?:[a-z0-9]+|#\d+|#x[0-9a-fA-F]+);$", context_before.strip(), re.IGNORECASE):
                return True, "Reflected", f"Payload XSS '{injected_payload}' (hoặc phần '{testable_part}') được phản chiếu lại.", XSS_ERROR_NAME_REFLECTED, XSS_CWE_ID, XSS_OWASP_CATEGORY
    event_handler_signature_in_payload = r"on[a-zA-Z]+\s*=\s*['\"]?\s*(?:alert|prompt|confirm)\s*\(|javascript:"
    if re.search(event_handler_signature_in_payload, injected_payload, re.IGNORECASE):
        match_on_event_keyword = re.search(r"(on[a-zA-Z]+\s*=)", injected_payload, re.IGNORECASE)
        if match_on_event_keyword:
            on_event_part_keyword = match_on_event_keyword.group(1)
            for m in re.finditer(re.escape(on_event_part_keyword), response_text, re.IGNORECASE):
                start_pos = m.start()
                context_after_on_event = response_text[m.end() : m.end() + 35]
                if re.search(r"['\"]?\s*(?:alert|prompt|confirm)\s*\(|javascript:", context_after_on_event, re.IGNORECASE):
                    context_before_on_event = response_text[max(0, start_pos - 10) : start_pos]
                    if not re.search(r"&(?:[a-z0-9]+|#\d+|#x[0-9a-fA-F]+);$", context_before_on_event.strip(), re.IGNORECASE):
                         return True, "Reflected (Event Handler)", f"Phát hiện event handler XSS tiềm năng từ '{injected_payload}'.", XSS_ERROR_NAME_REFLECTED, XSS_CWE_ID, XSS_OWASP_CATEGORY
    return False, None, None, None, None, None


class WebScannerService:
    def __init__(self, num_threads=10):
        self.num_threads = num_threads
        print(f"[Service Init] WebScannerService initialized with {self.num_threads} threads.")

    def discover_urls_with_params(self, start_url, session, max_urls_to_check=5, thread_id="Crawler"):
        # (Giữ nguyên logic của hàm discover_urls_with_params từ phiên bản trước, đảm bảo có self)
        # ...
        urls_to_scan = set()
        queue = deque([start_url])
        crawled_urls = {start_url} 
        base_domain = urlparse(start_url).netloc
        # print(f"  [{thread_id}] Bắt đầu khám phá URL từ: {start_url}") # Bỏ print này để tool tự quản lý output
        crawl_count = 0
        max_crawl_depth_links = max_urls_to_check * 15 
        while queue and len(urls_to_scan) < max_urls_to_check and crawl_count < max_crawl_depth_links:
            current_url = queue.popleft(); crawl_count += 1
            try:
                headers_crawl = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 ServiceCrawler (Thread-{thread_id})'}
                response = session.get(current_url, timeout=7, verify=False, allow_redirects=True, headers=headers_crawl)
                response.raise_for_status()
                final_url_parsed = urlparse(response.url)
                if final_url_parsed.query: 
                    if response.url not in urls_to_scan: 
                        urls_to_scan.add(response.url)
                        # print(f"        [+] Tìm thấy URL có tham số để quét: {response.url} (Tổng: {len(urls_to_scan)})")
                    if len(urls_to_scan) >= max_urls_to_check: break
                if 'text/html' in response.headers.get('Content-Type', '').lower():
                    soup = BeautifulSoup(response.content, 'html.parser')
                    for link_tag in soup.find_all('a', href=True):
                        href = link_tag['href']
                        if not href or href.startswith('#') or href.lower().startswith(('mailto:', 'tel:')): continue
                        absolute_url = urljoin(response.url, href)
                        parsed_absolute_url = urlparse(absolute_url)
                        if (parsed_absolute_url.netloc == base_domain and
                                parsed_absolute_url.scheme in ['http', 'https'] and
                                absolute_url not in crawled_urls):
                            crawled_urls.add(absolute_url)
                            if parsed_absolute_url.query:
                                if absolute_url not in urls_to_scan:
                                    urls_to_scan.add(absolute_url)
                                    # print(f"        [+] Tìm thấy URL có tham số để quét: {absolute_url} (Tổng: {len(urls_to_scan)})")
                                if len(urls_to_scan) >= max_urls_to_check: break
                            if len(crawled_urls) < max_crawl_depth_links : queue.append(absolute_url)
                    if len(urls_to_scan) >= max_urls_to_check: break
            except requests.exceptions.RequestException: pass
            except Exception: pass
        return list(urls_to_scan)


        # Đổi tên từ scan_single_url_with_params để rõ ràng đây là job cho luồng
        # Logic của hàm này giữ nguyên như scan_single_url_with_params trước đó, chỉ thay đổi print
        # và đảm bảo nó là một phương thức của class (có self)
    def _scan_single_url_job(self, target_url, payloads_sqli, payloads_xss, session_for_thread, thread_id="N/A"):
        # print(f"  [ServiceScanJob-{thread_id}] Bắt đầu quét: {target_url}")
        parsed_url = urlparse(target_url)
        original_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        if not original_query_params:
            # print(f"  [ServiceScanJob-{thread_id}] URL không có tham số: {target_url}")
            return []

        job_findings = []
        baseline_response_time = 0.5 # Mặc định
        try:
            headers_baseline = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 BaselineCheck (Job-{thread_id})'}
            test_responses_times = []
            # Chỉ lấy baseline một lần để tiết kiệm thời gian cho mỗi job
            r_start = time.time()
            session_for_thread.get(target_url, timeout=7, verify=False, headers=headers_baseline)
            test_responses_times.append(time.time() - r_start)
            if test_responses_times:
                baseline_response_time = sum(test_responses_times) / len(test_responses_times)
            # print(f"    [DEBUG Job-{thread_id}] Baseline time for {target_url}: {baseline_response_time:.2f}s")
        except requests.exceptions.RequestException:
            # print(f"    [WARN Job-{thread_id}] Could not get baseline for {target_url}")
            pass # Tiếp tục với baseline mặc định

        for param_name, param_values in original_query_params.items():
            original_value = param_values[0] if param_values and param_values[0] else "testDefault123"
            # print(f"    [DEBUG Job-{thread_id}] Scanning Param: '{param_name}' with original value: '{original_value}' in URL: {target_url}")

            # --- Quét SQLi ---
            if payloads_sqli:
                # print(f"        [DEBUG Job-{thread_id}] Initiating SQLi scan for param '{param_name}'")
                for payload_file_key, sqli_payload_list in payloads_sqli.items():
                    # print(f"            [DEBUG Job-{thread_id}] Using SQLi payloads from: {payload_file_key}")
                    for payload in sqli_payload_list:
                        test_params_sqli = original_query_params.copy()
                        injected_value_sqli = original_value + payload 
                        test_params_sqli[param_name] = [injected_value_sqli]
                        modified_query_sqli = urlencode(test_params_sqli, doseq=True)
                        vuln_url_sqli = parsed_url._replace(query=modified_query_sqli).geturl()
                        
                        # print(f"                [DEBUG Job-{thread_id}] SQLi Test URL: {vuln_url_sqli}")
                        try:
                            headers_sqli = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 SQLiTest (Job-{thread_id})'}
                            start_req_time = time.time()
                            req_timeout = 15 if is_sqli_time_based_payload(payload) else 10
                            
                            response_sqli = session_for_thread.get(vuln_url_sqli, timeout=req_timeout, verify=False, headers=headers_sqli, allow_redirects=False)
                            response_time_sqli = time.time() - start_req_time
                            # print(f"                [DEBUG Job-{thread_id}] SQLi Status: {response_sqli.status_code} | Time: {response_time_sqli:.2f}s")
                            
                            is_vuln, det_method, evid, err_name, cwe, owasp = check_for_sqli(response_sqli.text, response_time_sqli, baseline_response_time, payload)
                            if is_vuln:
                                print(f"    [!!! SQLi VULN FOUND Job-{thread_id} !!!] URL: {vuln_url_sqli}, Param: {param_name}, Payload: {payload[:60]}")
                                finding_data = {
                                    "vulnerability_type": "SQLi", "vulnerable_url": vuln_url_sqli, "parameter": param_name,
                                    "payload_source_file": payload_file_key, "payload_used": payload,
                                    "detection_method": det_method, "evidence": evid,
                                    "http_status_code": response_sqli.status_code, "error_name": err_name,
                                    "cwe": cwe, "owasp_category": owasp, "loi": True
                                }
                                job_findings.append(finding_data)

                        except requests.exceptions.Timeout:
                            if is_sqli_time_based_payload(payload):
                                expected_delay = extract_sqli_sleep_duration(payload)
                                print(f"    [!!! SQLi TIMEOUT VULN Job-{thread_id} !!!] URL: {vuln_url_sqli}, Param: {param_name}, Payload: {payload[:60]}")
                                finding_data = {
                                    "vulnerability_type": "SQLi", "vulnerable_url": vuln_url_sqli, "parameter": param_name,
                                    "payload_source_file": payload_file_key, "payload_used": payload,
                                    "detection_method": "Time-based (Request Timeout)",
                                    "evidence": f"Request timed out after {req_timeout}s. Payload SQLi dự kiến gây trễ khoảng {expected_delay}s.",
                                    "http_status_code": "N/A (Timeout)", "error_name": SQLI_ERROR_NAME,
                                    "cwe": SQLI_CWE_ID, "owasp_category": SQLI_OWASP_CATEGORY, "loi": True
                                }
                                job_findings.append(finding_data)
                        except requests.exceptions.RequestException as e_req_sqli:
                            # print(f"                [WARN Job-{thread_id}] Request Exception (SQLi) for {vuln_url_sqli}: {e_req_sqli}")
                            pass
            
            # --- Quét XSS ---
            if payloads_xss:
                # print(f"        [DEBUG Job-{thread_id}] Initiating XSS scan for param '{param_name}'")
                for payload_file_key, xss_payload_list in payloads_xss.items():
                    # print(f"            [DEBUG Job-{thread_id}] Using XSS payloads from: {payload_file_key}")
                    for payload in xss_payload_list:
                        test_params_xss = original_query_params.copy()
                        # Với XSS, thường thay thế hoàn toàn giá trị tham số bằng payload
                        test_params_xss[param_name] = [payload] 
                        
                        modified_query_xss = urlencode(test_params_xss, doseq=True)
                        vuln_url_xss = parsed_url._replace(query=modified_query_xss).geturl()
                        # print(f"                [DEBUG Job-{thread_id}] XSS Test URL: {vuln_url_xss}")

                        try:
                            headers_xss = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 XSSTest (Job-{thread_id})'}
                            response_xss = session_for_thread.get(vuln_url_xss, timeout=10, verify=False, headers=headers_xss, allow_redirects=True) 
                            # print(f"                [DEBUG Job-{thread_id}] XSS Status: {response_xss.status_code}")
                            
                            is_vuln, det_method, evid, err_name, cwe, owasp = check_for_xss(response_xss.text, payload)
                            if is_vuln:
                                print(f"    [!!! XSS VULN FOUND Job-{thread_id} !!!] URL: {vuln_url_xss}, Param: {param_name}, Payload: {payload[:60]}")
                                finding_data = {
                                    "vulnerability_type": "XSS", "vulnerable_url": vuln_url_xss, "parameter": param_name,
                                    "payload_source_file": payload_file_key, "payload_used": payload,
                                    "detection_method": det_method, "evidence": evid,
                                    "http_status_code": response_xss.status_code, "error_name": err_name,
                                    "cwe": cwe, "owasp_category": owasp, "loi": True
                                }
                                job_findings.append(finding_data)
                        except requests.exceptions.RequestException as e_req_xss:
                            # print(f"                [WARN Job-{thread_id}] Request Exception (XSS) for {vuln_url_xss}: {e_req_xss}")
                            pass
        # print(f"  [ServiceScanJob-{thread_id}] Hoàn thành quét cho {target_url}. Tìm thấy {len(job_findings)} lỗi.")
        return job_findings 

    def scan_multiple_urls(self, urls_to_scan: list, 
                           payloads_sqli: dict, payloads_xss: dict, 
                           session_override=None, num_threads_override=None):
        """
        Quét một danh sách các URL đã cho, sử dụng đa luồng.
        """
        if not urls_to_scan:
            return []

        current_num_threads = num_threads_override if num_threads_override is not None else self.num_threads
        print(f"  [ServiceScanMultiple] Quét {len(urls_to_scan)} URLs với {current_num_threads} luồng.")
        
        all_findings = []
        
        # Sử dụng session_override nếu được cung cấp, nếu không tạo session mới cho toàn bộ quá trình này
        # Hoặc tốt hơn là mỗi luồng tạo session riêng nếu không có session_override
        # Trong trường hợp này, _scan_single_url_job sẽ nhận session_for_thread.
        # Chúng ta cần quyết định session được tạo ở đâu.
        # Nếu Tool truyền session, thì dùng nó. Nếu không, service tạo.
        
        # Giả định session_override là session dùng chung cho các luồng từ Tool
        session_to_use_for_jobs = session_override
        created_session_locally = False
        if not session_to_use_for_jobs:
            session_to_use_for_jobs = requests.Session()
            session_to_use_for_jobs.headers.update({'User-Agent': 'Mozilla/5.0 VulnScanner/1.1 ServiceScanPool'})
            created_session_locally = True
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=current_num_threads) as executor:
            future_to_url_map = {}
            for i, url in enumerate(urls_to_scan):
                # Mỗi job trong executor sẽ gọi _scan_single_url_job
                future = executor.submit(
                    self._scan_single_url_job, # Gọi phương thức của class
                    url,
                    payloads_sqli,
                    payloads_xss,
                    session_to_use_for_jobs, # Truyền session cho mỗi job
                    str(i + 1)
                )
                future_to_url_map[future] = url
            
            for future in concurrent.futures.as_completed(future_to_url_map):
                url_completed = future_to_url_map[future]
                try:
                    findings_from_url = future.result()
                    if findings_from_url:
                        all_findings.extend(findings_from_url)
                except Exception as exc:
                    print(f"  [ServiceScanMultiple] URL {url_completed} gây lỗi trong luồng: {exc}")
        
        if created_session_locally:
            session_to_use_for_jobs.close()
            
        all_findings.sort(key=lambda x: x.get('vulnerable_url', ''))
        print(f"  [ServiceScanMultiple] Hoàn thành quét {len(urls_to_scan)} URLs. Tổng lỗ hổng: {len(all_findings)}.")
        return all_findings


    def full_scan(self, initial_url, crawl_enabled=False, max_crawl_urls=5, 
                  pre_discovered_urls=None, 
                  skip_sqli=False, skip_xss=False, 
                  payloads_sqli={}, payloads_xss={},
                  session_override=None, num_threads_override=None):
        """
        Thực hiện quét toàn bộ: crawl (nếu cần) rồi quét các URL tìm được.
        """
        print(f"[ServiceFullScan] Bắt đầu full_scan cho: {initial_url}")
        active_session = session_override
        created_session_locally_full_scan = False
        if not active_session:
            active_session = requests.Session()
            active_session.headers.update({'User-Agent': 'Mozilla/5.0 VulnScanner/1.1 FullScanProcess'})
            created_session_locally_full_scan = True

        urls_to_process = []
        if pre_discovered_urls is not None:
            urls_to_process = pre_discovered_urls
            print(f"  [ServiceFullScan] Sử dụng danh sách URL đã khám phá trước: {len(urls_to_process)} URLs")
        else:
            parsed_initial_url = urlparse(initial_url)
            if parsed_initial_url.query:
                urls_to_process.append(initial_url)
            if crawl_enabled:
                print(f"  [ServiceFullScan] Bật crawl cho {initial_url}")
                discovered_urls = self.discover_urls_with_params(
                    initial_url, active_session, max_crawl_urls, thread_id="FullScanCrawler"
                )
                for d_url in discovered_urls:
                    if d_url not in urls_to_process:
                        urls_to_process.append(d_url)
        
        if not urls_to_process:
            msg = f"Không tìm thấy URL nào có tham số để quét cho {initial_url} (sau crawl nếu có)."
            print(f"  [ServiceFullScan] {msg}")
            if created_session_locally_full_scan: active_session.close()
            return {"initial_url": initial_url, "scanned_urls": [], "findings": [], "message": msg}

        # Gọi hàm quét danh sách URL
        findings = self.scan_multiple_urls(
            urls_to_process,
            payloads_sqli if not skip_sqli else {},
            payloads_xss if not skip_xss else {},
            session_override=active_session, # Truyền session đang hoạt động
            num_threads_override=num_threads_override
        )
        
        if created_session_locally_full_scan:
            active_session.close()
            
        return {"initial_url": initial_url, "scanned_urls": urls_to_process, "findings": findings}