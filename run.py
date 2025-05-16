# run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Chạy ở chế độ debug khi phát triển
    # Không dùng debug=True trong môi trường production
    app.run(debug=True, host='0.0.0.0', port=5000)