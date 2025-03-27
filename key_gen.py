from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Tạo khóa bí mật RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Lấy khóa công khai tương ứng
public_key = private_key.public_key()

# Lưu khóa bí mật xuống file (LƯU Ý: Bảo mật khóa bí mật này cẩn thận!)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() # Không mã hóa khóa bí mật
)

with open("private_key.pem", "wb") as f:
    f.write(private_key_pem)

# Lưu khóa công khai xuống file (có thể chia sẻ khóa công khai này)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as f:
    f.write(public_key_pem)

print("Khóa bí mật và khóa công khai đã được tạo và lưu vào file private_key.pem và public_key.pem")