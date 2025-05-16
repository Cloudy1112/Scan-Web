# app/utils/cwe_manager.py
import json
import os

_cwe_data_cache = None # Đổi tên biến cache để tránh xung đột tiềm ẩn

def load_cwe_data_from_file():
    global _cwe_data_cache
    if _cwe_data_cache is None: # Chỉ tải một lần
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Đường dẫn từ app/utils/ đến app/data/cwe_data.json
            data_file_path = os.path.join(current_dir, '..', 'data', 'cwe_data.json')
            
            with open(data_file_path, 'r', encoding='utf-8') as f:
                _cwe_data_cache = json.load(f)
            print(f"[CWEManager] Dữ liệu CWE đã được tải thành công từ: {data_file_path}")
        except FileNotFoundError:
            print(f"[LỖI CWEManager] Không tìm thấy file cwe_data.json tại: {data_file_path}")
            _cwe_data_cache = {}
        except json.JSONDecodeError as e:
            print(f"[LỖI CWEManager] File cwe_data.json không hợp lệ tại: {data_file_path}. Lỗi: {e}")
            _cwe_data_cache = {}
        except Exception as e:
            print(f"[LỖI CWEManager] Lỗi không xác định khi tải cwe_data.json: {e}")
            _cwe_data_cache = {}
    return _cwe_data_cache

def get_cwe_info(cwe_id):
    data = load_cwe_data_from_file()
    return data.get(cwe_id)

def get_all_cwe_ids_with_names():
    data = load_cwe_data_from_file()
    return {cwe_id: details.get("name", "Không có tên") for cwe_id, details in data.items()}

# Gọi hàm load một lần khi module được import để dữ liệu sẵn sàng
# Điều này xảy ra khi Flask khởi động và import các utils
if _cwe_data_cache is None: # Đảm bảo chỉ gọi một lần
    load_cwe_data_from_file()