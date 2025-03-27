import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import os

def chon_file():
    filename = filedialog.askopenfilename()
    if filename:
        normalized_path = os.path.abspath(filename)  # Normalize the file path
        file_path_var.set(normalized_path)
        result_text.insert(tk.END, f"Đã chọn file: {normalized_path}\n")

def ky_so_file():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showerror("Lỗi", "Vui lòng chọn file cần ký trước!")
        return

    if not os.path.exists(file_path):  # Check if the file exists
        messagebox.showerror("Lỗi", f"File không tồn tại: {file_path}")
        result_text.insert(tk.END, f"Lỗi: File không tồn tại: {file_path}\n")
        return

    result_text.insert(tk.END, f"Đang thực hiện ký số file: {file_path}...\n")

    try:
        # 1. Đọc dữ liệu file cần ký
        with open(file_path, "rb") as f:
            message = f.read()

        # 2. Tải khóa bí mật từ file (giả định "private_key.pem" cùng thư mục)
        private_key_path = os.path.abspath("private_key.pem")  # Ensure absolute path
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Khóa không mã hóa trong ví dụ này
                backend=default_backend()
            )

        # 3. Tạo chữ ký số
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 4. Hiển thị chữ ký số (dạng hex)
        signature_hex = signature.hex()
        result_text.insert(tk.END, "Chữ ký số (hex):\n")
        result_text.insert(tk.END, signature_hex + "\n\n")

        # 5. Lưu chữ ký số vào file .sig (cùng tên file gốc)
        signature_file_path = file_path + ".sig"
        with open(signature_file_path, "wb") as sig_file:
            sig_file.write(signature)
        result_text.insert(tk.END, f"Đã lưu chữ ký số vào file: {signature_file_path}\n")

        result_text.insert(tk.END, "Ký số file thành công!\n")

    except FileNotFoundError:
        messagebox.showerror("Lỗi", f"File không tồn tại: {file_path}")
        result_text.insert(tk.END, f"Lỗi: File không tồn tại: {file_path}\n")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Lỗi ký số file: {e}")
        result_text.insert(tk.END, f"Lỗi: {e}\n")

def xac_minh_chu_ky_file():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showerror("Lỗi", "Vui lòng chọn file cần xác minh chữ ký trước!")
        return

    if not os.path.exists(file_path):  # Check if the file exists
        messagebox.showerror("Lỗi", f"File không tồn tại: {file_path}")
        result_text.insert(tk.END, f"Lỗi: File không tồn tại: {file_path}\n")
        return

    result_text.insert(tk.END, f"Đang thực hiện xác minh chữ ký số file: {file_path}...\n")

    try:
        # 1. Đọc dữ liệu file cần xác minh
        with open(file_path, "rb") as f:
            message = f.read()

        # 2. Tải khóa công khai từ file (giả định "public_key.pem" cùng thư mục)
        public_key_path = os.path.abspath("public_key.pem")  # Ensure absolute path
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # 3. Đọc chữ ký số từ file .sig (giả định <tên_file>.sig cùng thư mục)
        signature_file_path = file_path + ".sig"
        with open(signature_file_path, "rb") as sig_file:
            signature = sig_file.read()

        # 4. Xác minh chữ ký số
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        result_text.insert(tk.END, "Chữ ký số HỢP LỆ!\n")

    except FileNotFoundError:
        messagebox.showerror("Lỗi", "File hoặc file chữ ký không tồn tại!")
        result_text.insert(tk.END, "Lỗi: File hoặc file chữ ký không tồn tại!\n")
    except InvalidSignature:
        result_text.insert(tk.END, "Chữ ký số KHÔNG HỢP LỆ!\n")
        messagebox.showerror("Lỗi", "Chữ ký số KHÔNG HỢP LỆ!")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Lỗi xác minh chữ ký: {e}")
        result_text.insert(tk.END, f"Lỗi: {e}\n")

# Tạo cửa sổ chính
window = tk.Tk()
window.title("Phần mềm Chữ ký Số Cơ Bản")
window.geometry("600x400") # Kích thước cửa sổ

# Biến để lưu đường dẫn file
file_path_var = tk.StringVar()

# Frame chứa các nút và ô nhập liệu chọn file
file_frame = tk.Frame(window)
file_frame.pack(pady=10)

file_label = tk.Label(file_frame, text="File:")
file_label.grid(row=0, column=0, padx=5)

file_entry = tk.Entry(file_frame, textvariable=file_path_var, width=50)
file_entry.grid(row=0, column=1, padx=5)

choose_file_button = tk.Button(file_frame, text="Chọn File", command=chon_file)
choose_file_button.grid(row=0, column=2, padx=5)

# Frame chứa các nút thao tác
action_frame = tk.Frame(window)
action_frame.pack(pady=10)

sign_button = tk.Button(action_frame, text="Ký Số File", command=ky_so_file)
sign_button.grid(row=0, column=0, padx=10)

verify_button = tk.Button(action_frame, text="Xác Minh Chữ Ký", command=xac_minh_chu_ky_file)
verify_button.grid(row=0, column=1, padx=10)

# Khu vực hiển thị kết quả (ScrolledText để có thanh cuộn nếu nhiều text)
result_text = scrolledtext.ScrolledText(window, height=10)
result_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
result_text.insert(tk.END, "Chào mừng đến với Phần mềm Chữ ký Số!\n")

# Chạy vòng lặp chính của Tkinter để hiển thị GUI
window.mainloop()