# app/utils/payload_manager.py
import os

def load_payloads_for_service(base_payloads_dir="payloads"): # Mặc định là thư mục payloads ở gốc dự án
    """
    Tải payloads từ cấu trúc thư mục đã định (SQLi/, XSS/).
    Đường dẫn base_payloads_dir nên là đường dẫn tuyệt đối hoặc tương đối từ gốc dự án.
    """
    all_payloads = {"SQLi": {}, "XSS": {}}
    
    # Xác định đường dẫn tuyệt đối đến thư mục payloads
    # Giả sử file này nằm trong app/utils, thư mục payloads nằm cùng cấp với app/
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    actual_payloads_path = os.path.join(project_root, base_payloads_dir)

    if not os.path.isdir(actual_payloads_path):
        print(f"[!] Không tìm thấy thư mục payload gốc: '{actual_payloads_path}'")
        return all_payloads

    for vuln_type_dir in os.listdir(actual_payloads_path): # SQLi, XSS
        vuln_type_path = os.path.join(actual_payloads_path, vuln_type_dir)
        if os.path.isdir(vuln_type_path) and vuln_type_dir in all_payloads:
            for root, _, files in os.walk(vuln_type_path):
                for filename in files:
                    if filename.endswith(".txt"):
                        filepath = os.path.join(root, filename)
                        relative_path_key = os.path.relpath(filepath, vuln_type_path)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                payloads_in_file = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                                if payloads_in_file:
                                    all_payloads[vuln_type_dir][relative_path_key] = payloads_in_file
                        except Exception as e:
                            print(f"[!] Lỗi khi tải payload từ {filepath} cho {vuln_type_dir}: {e}")
    
    total_sqli = sum(len(p) for p in all_payloads["SQLi"].values())
    total_xss = sum(len(p) for p in all_payloads["XSS"].values())
    print(f"[PayloadManager] Đã tải {total_sqli} payloads SQLi, {total_xss} payloads XSS.")
    return all_payloads