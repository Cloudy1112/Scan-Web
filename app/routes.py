# app/routes.py
from flask import Blueprint, render_template, request, jsonify, url_for
import os
import json
from datetime import datetime

from . import db
from .models import ScanHistory
# Import hàm chạy crew thay vì service trực tiếp
from .agents.vulnerability_scanner_crew import run_scanning_crew
# get_cwe_info, get_all_cwe_ids_with_names đã được đăng ký global qua context_processor

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    scan_results_data = None
    submitted_target_url = request.form.get('target_url', '').strip() if request.method == 'POST' else None

    if request.method == 'POST':
        target_url = submitted_target_url # Đã lấy ở trên
        enable_crawl = request.form.get('enable_crawl') == 'on'
        try:
            max_crawl_urls = int(request.form.get('max_crawl_urls', 5))
            if max_crawl_urls < 1: max_crawl_urls = 1
        except ValueError: max_crawl_urls = 5
        skip_sqli = request.form.get('skip_sqli') == 'on'
        skip_xss = request.form.get('skip_xss') == 'on'
        try: # Thêm num_threads từ form nếu muốn, hoặc để mặc định trong run_scanning_crew
            num_threads = int(request.form.get('num_threads', 10))
            if num_threads < 1: num_threads = 1
        except ValueError: num_threads = 10


        if not target_url:
            scan_results_data = {"error": "Vui lòng nhập URL mục tiêu."}
        elif not (target_url.startswith('http://') or target_url.startswith('https://')):
            scan_results_data = {"error": "URL không hợp lệ. Vui lòng bao gồm http:// hoặc https://"}
        elif skip_sqli and skip_xss:
            scan_results_data = {"error": "Vui lòng chọn ít nhất một loại lỗ hổng để quét."}
        else:
            try:
                print(f"[*] ROUTE: Nhận yêu cầu quét cho: {target_url} (Crawl: {enable_crawl}, ...)")
                
                # Gọi hàm chạy crew từ vulnerability_scanner_crew.py
                scan_data_from_crew = run_scanning_crew(
                    initial_url=target_url,
                    crawl_enabled=enable_crawl,
                    max_crawl_urls=max_crawl_urls,
                    skip_sqli=skip_sqli,
                    skip_xss=skip_xss,
                    num_threads=num_threads 
                )
                scan_results_data = scan_data_from_crew

                if not scan_results_data.get("error") and "findings" in scan_results_data:
                    try:
                        findings_to_save = scan_results_data.get('findings', [])
                        # Đảm bảo findings_to_save là list (có thể tool trả về string)
                        if isinstance(findings_to_save, str):
                            try:
                                findings_to_save = json.loads(findings_to_save)
                            except json.JSONDecodeError:
                                print(f"[Warning Route] findings từ crew không phải JSON hợp lệ: {findings_to_save}")
                                findings_to_save = [{"error_parsing_findings": str(findings_to_save)}]


                        new_scan_entry = ScanHistory(
                            target_url=scan_results_data.get('initial_url', target_url),
                            findings_json=json.dumps(findings_to_save),
                            crawl_enabled=enable_crawl,
                            max_crawl_urls=max_crawl_urls if enable_crawl else None,
                            num_findings=len(findings_to_save) if isinstance(findings_to_save, list) else 0
                            # Thêm summary nếu muốn lưu:
                            # summary_llm = scan_results_data.get("summary_by_llm", "")
                        )
                        db.session.add(new_scan_entry)
                        db.session.commit()
                        print(f"[*] ROUTE: Đã lưu kết quả quét cho '{target_url}' vào lịch sử.")
                    except Exception as db_error:
                        db.session.rollback()
                        print(f"[Error Routes] Lỗi khi lưu vào lịch sử quét: {db_error}")
                        if scan_results_data:
                             scan_results_data["warning_db"] = "Không thể lưu kết quả vào lịch sử."
                        else:
                             scan_results_data = {"error": "Lỗi hệ thống khi lưu lịch sử."}
            except Exception as e:
                print(f"[Error Routes] Lỗi nghiêm trọng trong quá trình xử lý quét từ route: {e}")
                import traceback
                traceback.print_exc()
                scan_results_data = {"error": f"Lỗi hệ thống không mong muốn: {str(e)}"}
        
    return render_template('index.html', 
                           results=scan_results_data, 
                           submitted_url=submitted_target_url,
                           is_history_view=False)

# Các route /cwe, /history, /history/<id> giữ nguyên như phiên bản trước
@bp.route('/cwe', methods=['GET'])
def cwe_list():
    from .utils.cwe_manager import get_all_cwe_ids_with_names
    cwe_summary = get_all_cwe_ids_with_names()
    return render_template('cwe_list.html', cwe_summary=cwe_summary)

@bp.route('/cwe/<cwe_id>', methods=['GET'])
def cwe_detail(cwe_id):
    from .utils.cwe_manager import get_cwe_info
    cwe_info_data = get_cwe_info(cwe_id)
    if not cwe_info_data:
        return render_template('cwe_not_found.html', cwe_id=cwe_id), 404
    return render_template('cwe_detail.html', cwe_id=cwe_id, cwe_info=cwe_info_data)

@bp.route('/history', methods=['GET'])
def scan_history_list():
    page = request.args.get('page', 1, type=int)
    try:
        history_entries = ScanHistory.query.order_by(ScanHistory.scan_timestamp.desc()).paginate(page=page, per_page=10)
    except Exception as e:
        print(f"[Error Routes] Lỗi khi truy vấn lịch sử: {e}")
        history_entries = None
    return render_template('scan_history.html', history_entries=history_entries)

@bp.route('/history/<int:scan_id>', methods=['GET'])
def scan_history_detail(scan_id):
    scan_entry = db.session.get(ScanHistory, scan_id)
    if not scan_entry:
        from flask import abort
        abort(404)
    findings = json.loads(scan_entry.findings_json) if scan_entry.findings_json else []
    results_for_template = {
        "initial_url": scan_entry.target_url,
        "scanned_urls": [scan_entry.target_url],
        "findings": findings,
        "scan_timestamp_from_history": scan_entry.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
        "message": f"Xem lại kết quả quét cho {scan_entry.target_url} vào lúc {scan_entry.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
        # Nếu bạn lưu summary của LLM vào DB, hãy lấy ra ở đây
        # "summary_by_llm": scan_entry.summary_llm_column if hasattr(scan_entry, 'summary_llm_column') else "Tóm tắt không có sẵn."
    }
    return render_template('index.html', 
                           results=results_for_template, 
                           submitted_url=scan_entry.target_url,
                           is_history_view=True)