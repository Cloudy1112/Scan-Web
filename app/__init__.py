# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from .utils.cwe_manager import get_cwe_info # Đảm bảo import này đúng

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    
    # Cấu hình SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'data', 'scan_history.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24) # Thêm secret key cho session/flash messages nếu cần

    db.init_app(app)

    from . import routes # Import routes sau khi app và db được cấu hình một phần
    app.register_blueprint(routes.bp)

    @app.context_processor
    def utility_processor():
        # Hàm này làm cho get_cwe_info có sẵn trong tất cả các template Jinja2
        return dict(get_cwe_details_for_template=get_cwe_info)
    
    with app.app_context():
        from . import models # Import models ở đây để tránh circular import và đảm bảo app context
        try:
            db.create_all()
            print(f"Cơ sở dữ liệu được kiểm tra/tạo tại: {db_path}")
        except Exception as e:
            print(f"Lỗi khi tạo bảng cơ sở dữ liệu: {e}")
            print("Hãy đảm bảo thư mục 'app/data/' tồn tại và có quyền ghi.")


    return app