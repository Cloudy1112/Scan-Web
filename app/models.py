# app/models.py
from . import db # Import db từ __init__.py cùng cấp
from datetime import datetime

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Lưu kết quả findings dưới dạng JSON string
    findings_json = db.Column(db.Text, nullable=True) 
    # Các thông tin khác bạn muốn lưu
    crawl_enabled = db.Column(db.Boolean, default=False)
    max_crawl_urls = db.Column(db.Integer, nullable=True)
    num_findings = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<ScanHistory {self.id} - {self.target_url}>'