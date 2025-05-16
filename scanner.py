import requests
import json
import os
import argparse
import re
import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import time
from collections import deque
import concurrent.futures # << Thêm thư viện này

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from webtech import WebTech
except ImportError:
    print("[-] Thư viện 'webtech' chưa được cài đặt (pip install webtech). Chức năng phát hiện công nghệ sẽ bị bỏ qua.")
    WebTech = None

# --- Hằng số (giữ nguyên) ---
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
XSS_REFLECTED_MARKER_PREFIX = "XSSscanMkr"
XSS_CWE_ID = "CWE-79"
XSS_OWASP_CATEGORY = "A03:2021-Injection"
XSS_ERROR_NAME_REFLECTED = "Reflected Cross-Site Scripting (XSS)"

# --- Các hàm tiện ích (get_technologies, load_payloads, is_sqli_time_based_payload, extract_sqli_sleep_duration, check_for_sqli, check_for_xss giữ nguyên) ---
# ... (Dán các hàm này từ phiên bản trước vào đây, không thay đổi nội dung của chúng) ...
def get_technologies(url, session):
    if not WebTech:
        return {"server_header": "N/A", "technologies": []}
    tech_info = {"server_header": "N/A", "technologies": []}
    headers_req = {'User-Agent': 'Mozilla/5.0 VulnScanner/1.1 TechDetect'}
    try:
        response = session.get(url, timeout=10, verify=False, headers=headers_req)
        response.raise_for_status()
        tech_info["server_header"] = response.headers.get("Server", "N/A")
        wt = WebTech() 
        detected_techs = []
        try:
            tech_results_obj = wt.analyze(response.url, response_headers=response.headers, response_html=response.content)
            if isinstance(tech_results_obj, dict):
                for tech_name_key in tech_results_obj:
                    tech_name = tech_results_obj[tech_name_key].get('name', tech_name_key)
                    version = tech_results_obj[tech_name_key].get('version')
                    full_name = tech_name
                    if version: full_name += f" ({version})"
                    detected_techs.append(full_name)
            elif isinstance(tech_results_obj, list):
                 for item in tech_results_obj:
                    tech_name = item.get('name')
                    version = item.get('version')
                    if tech_name:
                        full_name = tech_name
                        if version: full_name += f" ({version})"
                        detected_techs.append(full_name)
        except AttributeError: 
            try:
                wt_sfr = WebTech(options={'json': False})
                tech_results_list = wt_sfr.start_from_response(response)
                if isinstance(tech_results_list, list):
                    for tech_item in tech_results_list:
                        tech_name = tech_item.get('name')
                        tech_version = tech_item.get('version')
                        if tech_name:
                            full_name = tech_name
                            if tech_version: full_name += f" ({tech_version})"
                            detected_techs.append(full_name)
            except Exception as e_sfr: print(f"[!] Lỗi webtech.start_from_response ({url}): {e_sfr}")
        except Exception as e_analyze: print(f"[!] Lỗi webtech.analyze ({url}): {e_analyze}")
        tech_info["technologies"] = list(set(detected_techs))
    except requests.exceptions.RequestException as e_req: print(f"[!] Lỗi request (webtech) cho {url}: {e_req}")
    except Exception as e_main: print(f"[!] Lỗi không mong muốn (webtech) cho {url}: {e_main}")
    return tech_info

def load_payloads(base_payloads_dir="payloads"):
    all_payloads = {"SQLi": {}, "XSS": {}}
    if not os.path.isdir(base_payloads_dir):
        print(f"[!] Không tìm thấy thư mục payload gốc: '{base_payloads_dir}'")
        return all_payloads
    for vuln_type_dir in os.listdir(base_payloads_dir):
        vuln_type_path = os.path.join(base_payloads_dir, vuln_type_dir)
        if os.path.isdir(vuln_type_path) and vuln_type_dir in all_payloads:
            for root, _, files in os.walk(vuln_type_path):
                for filename in files:
                    if filename.endswith(".txt"):
                        filepath = os.path.join(root, filename)
                        relative_path_key = os.path.relpath(filepath, vuln_type_path)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                payloads_in_file = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                                if payloads_in_file: all_payloads[vuln_type_dir][relative_path_key] = payloads_in_file
                        except Exception as e: print(f"[!] Lỗi khi tải payload từ {filepath} cho {vuln_type_dir}: {e}")
    return all_payloads

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
                return True, "Reflected", f"Payload XSS '{injected_payload}' (phần '{testable_part}') phản chiếu.", XSS_ERROR_NAME_REFLECTED, XSS_CWE_ID, XSS_OWASP_CATEGORY
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
                         return True, "Reflected (Event Handler)", f"Event handler XSS tiềm năng từ '{injected_payload}'.", XSS_ERROR_NAME_REFLECTED, XSS_CWE_ID, XSS_OWASP_CATEGORY
    return False, None, None, None, None, None

# --- Hàm quét một URL (giữ nguyên, sẽ được gọi bởi các luồng) ---
def scan_single_url_with_params(target_url, payloads_sqli, payloads_xss, session_for_thread):
    # Hàm này gần như giữ nguyên, chỉ thay session bằng session_for_thread
    # và print ít hơn để output không bị rối khi chạy đa luồng
    print(f"[*] Bắt đầu quét: {target_url}")
    parsed_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    if not original_query_params: return [] # Không có param, không quét

    thread_findings = [] # Kết quả của luồng này
    baseline_response_time = 0.5
    try:
        headers_baseline = {'User-Agent': 'Mozilla/5.0 VulnScanner/1.1 BaselineCheck'}
        test_responses_times = []
        for _ in range(1): # Giảm số lần lấy baseline trong luồng để nhanh hơn
            r_start = time.time()
            session_for_thread.get(target_url, timeout=7, verify=False, headers=headers_baseline)
            test_responses_times.append(time.time() - r_start)
            # time.sleep(0.05) # Giảm thời gian nghỉ
        if test_responses_times: baseline_response_time = sum(test_responses_times) / len(test_responses_times)
        # print(f"    [*] Baseline cho {target_url}: {baseline_response_time:.2f}s") # Ít print hơn
    except requests.exceptions.RequestException: pass # Ít print lỗi baseline

    for param_name, param_values in original_query_params.items():
        original_value = param_values[0] if param_values and param_values[0] else "testVal123"
        # print(f"    [*] Tham số: '{param_name}' (URL: {target_url})") # Ít print

        if payloads_sqli:
            # print(f"        [*] --- SQLi cho '{param_name}' ---") # Ít print
            for payload_file_key, sqli_payload_list in payloads_sqli.items():
                for payload in sqli_payload_list:
                    test_params_sqli = original_query_params.copy()
                    injected_value_sqli = original_value + payload 
                    test_params_sqli[param_name] = [injected_value_sqli]
                    modified_query_sqli = urlencode(test_params_sqli, doseq=True)
                    vuln_url_sqli = parsed_url._replace(query=modified_query_sqli).geturl()
                    try:
                        headers_sqli = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 SQLiTest'}
                        start_req_time = time.time()
                        req_timeout = 15 if is_sqli_time_based_payload(payload) else 10
                        response_sqli = session_for_thread.get(vuln_url_sqli, timeout=req_timeout, verify=False, headers=headers_sqli, allow_redirects=False)
                        response_time_sqli = time.time() - start_req_time
                        is_vuln, det_method, evid, err_name, cwe, owasp = check_for_sqli(response_sqli.text, response_time_sqli, baseline_response_time, payload)
                        if is_vuln:
                            finding_data = {"vulnerability_type": "SQLi", "vulnerable_url": vuln_url_sqli, "parameter": param_name, "payload_source_file": payload_file_key, "payload_used": payload, "detection_method": det_method, "evidence": evid, "http_status_code": response_sqli.status_code, "error_name": err_name, "cwe": cwe, "owasp_category": owasp, "loi": True}
                            thread_findings.append(finding_data)
                            print(f"\n    [+] SQLi tìm thấy: {vuln_url_sqli} (Param: {param_name}, Payload: {payload[:30]}...)") # Print khi tìm thấy
                    except requests.exceptions.Timeout:
                        if is_sqli_time_based_payload(payload):
                            expected_delay = extract_sqli_sleep_duration(payload)
                            finding_data = {"vulnerability_type": "SQLi", "vulnerable_url": vuln_url_sqli, "parameter": param_name, "payload_source_file": payload_file_key, "payload_used": payload, "detection_method": "Time-based (Request Timeout)", "evidence": f"Timeout ({req_timeout}s). Dự kiến trễ {expected_delay}s.", "http_status_code": "N/A (Timeout)", "error_name": SQLI_ERROR_NAME, "cwe": SQLI_CWE_ID, "owasp_category": SQLI_OWASP_CATEGORY, "loi": True}
                            thread_findings.append(finding_data)
                            print(f"\n    [+] SQLi Time-based (Timeout): {vuln_url_sqli} (Param: {param_name}, Payload: {payload[:30]}...)")
                    except requests.exceptions.RequestException: pass
        
        if payloads_xss:
            # print(f"        [*] --- XSS cho '{param_name}' ---") # Ít print
            for payload_file_key, xss_payload_list in payloads_xss.items():
                for payload in xss_payload_list:
                    test_params_xss = original_query_params.copy()
                    test_params_xss[param_name] = [payload] 
                    modified_query_xss = urlencode(test_params_xss, doseq=True)
                    vuln_url_xss = parsed_url._replace(query=modified_query_xss).geturl()
                    try:
                        headers_xss = {'User-Agent': f'Mozilla/5.0 VulnScanner/1.1 XSSTest'}
                        response_xss = session_for_thread.get(vuln_url_xss, timeout=10, verify=False, headers=headers_xss, allow_redirects=True)
                        is_vuln, det_method, evid, err_name, cwe, owasp = check_for_xss(response_xss.text, payload)
                        if is_vuln:
                            finding_data = {"vulnerability_type": "XSS", "vulnerable_url": vuln_url_xss, "parameter": param_name, "payload_source_file": payload_file_key, "payload_used": payload, "detection_method": det_method, "evidence": evid, "http_status_code": response_xss.status_code, "error_name": err_name, "cwe": cwe, "owasp_category": owasp, "loi": True}
                            thread_findings.append(finding_data)
                            print(f"\n    [+] XSS tìm thấy: {vuln_url_xss} (Param: {param_name}, Payload: {payload[:30]}...)")
                    except requests.exceptions.RequestException: pass
    return thread_findings


# --- Hàm Crawl (giữ nguyên) ---
def discover_urls_with_params(start_url, session, max_urls_to_check=10):
    # ... (giữ nguyên logic từ phiên bản trước) ...
    urls_to_scan = set()
    queue = deque([start_url])
    crawled_urls = {start_url} 
    base_domain = urlparse(start_url).netloc
    print(f"[*] Bắt đầu khám phá URL từ: {start_url} (giới hạn {max_urls_to_check} URL có tham số)")
    crawl_count = 0
    max_crawl_depth_links = max_urls_to_check * 15 
    while queue and len(urls_to_scan) < max_urls_to_check and crawl_count < max_crawl_depth_links:
        current_url = queue.popleft(); crawl_count += 1
        try:
            headers_crawl = {'User-Agent': 'Mozilla/5.0 VulnScanner/1.1 Crawler'}
            response = session.get(current_url, timeout=7, verify=False, allow_redirects=True, headers=headers_crawl)
            response.raise_for_status()
            final_url_parsed = urlparse(response.url)
            if final_url_parsed.query: 
                if response.url not in urls_to_scan: 
                    urls_to_scan.add(response.url)
                    print(f"        [+] Tìm thấy URL có tham số để quét: {response.url} (Tổng: {len(urls_to_scan)})")
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
                                print(f"        [+] Tìm thấy URL có tham số để quét: {absolute_url} (Tổng: {len(urls_to_scan)})")
                            if len(urls_to_scan) >= max_urls_to_check: break
                        if len(crawled_urls) < max_crawl_depth_links : queue.append(absolute_url)
                if len(urls_to_scan) >= max_urls_to_check: break
        except requests.exceptions.RequestException: pass
        except Exception: pass
    return list(urls_to_scan)

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Công cụ quét SQL Injection và XSS đa luồng.")
    # ... (Thêm tùy chọn --threads) ...
    parser.add_argument("url", help="URL bắt đầu để quét và khám phá.")
    parser.add_argument("-p", "--payloads_dir", default="payloads", help="Thư mục gốc chứa thư mục con SQLi và XSS.")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Tên file JSON output.")
    parser.add_argument("-ua", "--user_agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 VulnScanner/1.1", help="User-Agent")
    parser.add_argument("--crawl", action="store_true", help="Bật tính năng khám phá URL trên cùng domain.")
    parser.add_argument("--max_crawl_scan_urls", type=int, default=5, help="Số URL có tham số tối đa sẽ quét sau khi khám phá.")
    parser.add_argument("--skip_sqli", action="store_true", help="Bỏ qua quét SQL Injection.")
    parser.add_argument("--skip_xss", action="store_true", help="Bỏ qua quét Cross-Site Scripting.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Số lượng luồng đồng thời để quét URL (mặc định: 10).")


    args = parser.parse_args()

    # Không tạo session global nữa, mỗi luồng sẽ có session riêng nếu cần
    # Hoặc có thể truyền một session dùng chung nếu nó thread-safe cho mục đích đọc
    # Tuy nhiên, để đơn giản và tránh vấn đề tiềm ẩn, mỗi task trong executor có thể tạo session riêng
    # Hoặc chúng ta tạo 1 session chính và truyền nó vào, requests.Session() thường là thread-safe cho các thao tác GET.
    main_session = requests.Session()
    main_session.headers.update({'User-Agent': args.user_agent}) 


    print(f"[*] Mục tiêu ban đầu: {args.url}")
    print(f"[*] Thư mục payloads: {os.path.abspath(args.payloads_dir)}")
    print(f"[*] Số luồng: {args.threads}")
    # ... (in thông tin khác) ...

    loaded_payloads = load_payloads(args.payloads_dir)
    payloads_sqli_to_use = loaded_payloads.get("SQLi", {}) if not args.skip_sqli else {}
    payloads_xss_to_use = loaded_payloads.get("XSS", {}) if not args.skip_xss else {}
    # ... (kiểm tra và in số lượng payload) ...
    if not payloads_sqli_to_use and not args.skip_sqli: print("[!] Không tải được payload SQLi hoặc đã chọn bỏ qua.")
    if not payloads_xss_to_use and not args.skip_xss: print("[!] Không tải được payload XSS hoặc đã chọn bỏ qua.")
    if not payloads_sqli_to_use and not payloads_xss_to_use: print("[!] Không có payload nào được tải. Kết thúc."); return
    total_sqli_payloads = sum(len(p) for p in payloads_sqli_to_use.values())
    total_xss_payloads = sum(len(p) for p in payloads_xss_to_use.values())
    if not args.skip_sqli: print(f"[*] Đã tải {total_sqli_payloads} payloads SQLi từ {len(payloads_sqli_to_use)} file(s).")
    if not args.skip_xss: print(f"[*] Đã tải {total_xss_payloads} payloads XSS từ {len(payloads_xss_to_use)} file(s).")


    print("[*] Đang phát hiện công nghệ web cho URL ban đầu...")
    tech_info = get_technologies(args.url, main_session) # Dùng main_session
    print(f"    Server: {tech_info['server_header']}")
    print(f"    Công nghệ: {', '.join(tech_info['technologies']) if tech_info['technologies'] else 'Không phát hiện được'}")

    urls_to_process = []
    initial_parsed_url = urlparse(args.url)
    if initial_parsed_url.query:
        print(f"[*] URL ban đầu '{args.url}' có tham số, sẽ được đưa vào danh sách quét.")
        if args.url not in urls_to_process: urls_to_process.append(args.url)
    else:
        if not args.crawl : print(f"[*] URL ban đầu '{args.url}' không có tham số GET và không bật chế độ crawl.")
        else: print(f"[*] URL ban đầu '{args.url}' không có tham số GET trực tiếp. Sẽ dựa vào crawler.")

    if args.crawl:
        discovered_param_urls = discover_urls_with_params(args.url, main_session, max_urls_to_check=args.max_crawl_scan_urls) # Dùng main_session
        for d_url in discovered_param_urls:
            if d_url not in urls_to_process:
                urls_to_process.append(d_url)
    
    if not urls_to_process:
        print("[*] Không tìm thấy URL nào có tham số GET để quét. Kết thúc.")
        # ... (ghi file JSON rỗng) ...
        return

    print(f"\n[*] Tổng cộng có {len(urls_to_process)} URL sẽ được quét với tối đa {args.threads} luồng:")
    for u_idx, u in enumerate(urls_to_process): print(f"    {u_idx+1}. {u}")

    all_findings_overall = []
    
    # --- Sử dụng ThreadPoolExecutor ---
    # Tạo một session mới cho mỗi luồng hoặc truyền main_session (requests.Session thường thread-safe cho GET)
    # Để an toàn hơn, mỗi luồng có thể tạo session riêng, nhưng sẽ tốn tài nguyên hơn.
    # Ở đây, ta sẽ truyền main_session.
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Tạo một future cho mỗi URL cần quét
        future_to_url = {
            executor.submit(
                scan_single_url_with_params, 
                url, 
                payloads_sqli_to_use, 
                payloads_xss_to_use, 
                main_session # Truyền session dùng chung
            ): url 
            for url in urls_to_process
        }
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings_from_url = future.result() # Lấy kết quả từ luồng (là một list các findings)
                if findings_from_url:
                    all_findings_overall.extend(findings_from_url)
                    # print(f"    [*] Hoàn thành quét cho {url}, tìm thấy {len(findings_from_url)} lỗ hổng tiềm năng.")
            except Exception as exc:
                print(f"[!] URL {url} gây ra lỗi trong quá trình quét đa luồng: {exc}")
    
    # Sắp xếp kết quả cuối cùng (tùy chọn, ví dụ theo URL)
    all_findings_overall.sort(key=lambda x: x.get('vulnerable_url', ''))


    # ... (phần tổng hợp và ghi kết quả JSON giữ nguyên) ...
    results_data = {
        "scan_target_initial": args.url,
        "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        "server_info_initial": tech_info,
        "scanned_urls_with_params": urls_to_process,
        "findings": all_findings_overall
    }
    json_output_string = json.dumps(results_data, indent=4, ensure_ascii=False)
    print("\n--- KẾT QUẢ QUÉT TỔNG HỢP (JSON) ---")
    print(json_output_string)
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=4, ensure_ascii=False)
        print(f"\n[+] Kết quả quét đã được lưu vào: {args.output}")
    except IOError as e: print(f"[!] Lỗi khi lưu kết quả vào {args.output}: {e}")
    if not all_findings_overall: print("\n[*] Không phát hiện lỗ hổng SQLi/XSS nào trên các URL đã quét.")
    else: print(f"\n[*] Quét hoàn tất. Tìm thấy {len(all_findings_overall)} lỗ hổng tiềm năng trên các URL đã quét.")

if __name__ == "__main__":
    main()