from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog

# Chọn file dữ liệu gốc để xác minh chữ ký
data_file_path = filedialog.askopenfilename(title="Chọn file dữ liệu gốc để xác minh")
if not data_file_path:
    print("Người dùng đã hủy chọn file dữ liệu gốc.")
    exit()

# Chọn file chữ ký số
signature_file_path = filedialog.askopenfilename(title="Chọn file chữ ký số (.sig)")
if not signature_file_path:
    print("Người dùng đã hủy chọn file chữ ký số.")
    exit()

try:
    # Đọc dữ liệu gốc từ file
    with open(data_file_path, 'rb') as data_file:
        message = data_file.read()

    # Tải khóa công khai từ file
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Đọc chữ ký số từ file đã chọn
    with open(signature_file_path, "rb") as sig_file:
        signature = sig_file.read()

    # Xác minh chữ ký số
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Chữ ký số hợp lệ!")

except FileNotFoundError:
    print("Lỗi: File dữ liệu gốc hoặc file chữ ký không tồn tại!")
except InvalidSignature:
    print("Chữ ký số KHÔNG hợp lệ!")
except Exception as e:
    print("Lỗi xác minh chữ ký:", e)
    print("Chi tiết lỗi:", e)