from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog


# test message
file_path = filedialog.askopenfilename()
with open(file_path, 'rb') as file:
    message = file.read()

# Tải khóa cá nhân từ file
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

# Lưu chữ ký số xuống file
with open("signature.bin", "wb") as sig_file:
    sig_file.write(signature)
    
print("Chữ ký số đã được lưu vào file signature.bin")