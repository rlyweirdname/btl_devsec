from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Giả sử chúng ta có dữ liệu cần ký
message = b"Day la du lieu can ky"

# Tải khóa bí mật từ file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Tạo chữ ký số
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Chữ ký số đã được tạo:")
print(signature.hex())

# Lưu chữ ký số xuống file (tùy chọn)
with open("signature.bin", "wb") as sig_file:
    sig_file.write(signature)

# Tải khóa công khai từ file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Xác minh chữ ký số
try:
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
except InvalidSignature:
    print("Chữ ký số KHÔNG hợp lệ!")
except Exception as e:
    print("Lỗi xác minh chữ ký:", e)