# **Phần mềm chữ ký điện tử MHK**

## **Giới thiệu**
Dự án này triển khai một hệ thống chữ ký số dựa trên thuật toán **Merkle-Hellman Knapsack Cryptosystem (MHK)**. Hệ thống bao gồm các chức năng:
- Tạo khóa công khai và khóa bí mật.
- Ký thông điệp bằng khóa bí mật.
- Xác minh chữ ký bằng khóa công khai.
- Mã hóa và giải mã thông điệp (tùy chọn).

Giao diện đồ họa (GUI) được xây dựng bằng **Tkinter**, cho phép người dùng dễ dàng thao tác với hệ thống.

---

## **Tính năng**
1. **Tạo khóa**:
   - Tạo khóa công khai và khóa bí mật dựa trên kích thước khóa do người dùng chỉ định.
   - Hiển thị khóa công khai (B, q, r) và khóa bí mật (W).

2. **Ký thông điệp**:
   - Ký một thông điệp bằng khóa bí mật.
   - Hiển thị chữ ký số (S).

3. **Xác minh chữ ký**:
   - Xác minh chữ ký số bằng khóa công khai.
   - Hiển thị kết quả xác minh (Hợp lệ hoặc Không hợp lệ).

4. **Tải thông điệp từ tệp**:
   - Cho phép người dùng tải thông điệp từ một tệp văn bản.

5. **Xóa dữ liệu**:
   - Xóa tất cả các trường nhập liệu và đặt lại khóa.

---

## **Yêu cầu hệ thống**
- **Python**: Phiên bản 3.8 trở lên.
- **Thư viện**:
  - `tkinter` (có sẵn trong Python).
  - `hashlib` (có sẵn trong Python).

---

## **Cách sử dụng**

### **1. Chạy chương trình**
- Mở terminal hoặc command prompt.
- Chạy lệnh:
  ```bash
  python gui2.py
  ```

### **2. Giao diện chính**
- **Tạo khóa**:
  - Nhập kích thước khóa (mặc định là 8).
  - Nhấn nút **"Tạo khóa"** để tạo khóa công khai và khóa bí mật.
- **Ký thông điệp**:
  - Nhập thông điệp vào ô **"Thông điệp (M)"** hoặc tải từ tệp.
  - Nhấn nút **"Ký thông điệp"** để tạo chữ ký số.
- **Xác minh chữ ký**:
  - Nhấn nút **"Xác minh chữ ký"** để kiểm tra tính hợp lệ của chữ ký.
- **Xóa dữ liệu**:
  - Nhấn **"Xóa tất cả"** để xóa toàn bộ dữ liệu và đặt lại khóa.

---

## **Cấu trúc dự án**
```plaintext
btl_devsec/
├── gui2.py                # Giao diện chính của hệ thống chữ ký số
├── mh_process.py          # Các hàm xử lý thuật toán MHK
├── test.txt               # Tệp mẫu chứa thông điệp để thử nghiệm
└── README.md              # Tài liệu hướng dẫn
```

---

## **Hướng dẫn chi tiết**

### **1. Tạo khóa**
- Nhập kích thước khóa (ví dụ: `8`, `16`, `32`).
- Nhấn **"Tạo khóa"**.
- Khóa công khai và khóa bí mật sẽ được hiển thị trong giao diện.

### **2. Ký thông điệp**
- Nhập thông điệp vào ô **"Thông điệp (M)"** hoặc nhấn **"Tải từ tệp..."** để tải thông điệp từ tệp.
- Nhấn **"Ký thông điệp"**.
- Chữ ký số (S) sẽ được hiển thị trong ô **"Chữ ký (S)"**.

### **3. Xác minh chữ ký**
- Nhấn **"Xác minh chữ ký"**.
- Kết quả xác minh sẽ được hiển thị trong nhật ký (Log).

### **4. Xóa dữ liệu**
- Nhấn **"Xóa tất cả"** để xóa toàn bộ dữ liệu và đặt lại khóa.

---

## **Ví dụ**
### **Tạo khóa**
- Kích thước khóa: `8`.
- Khóa công khai:
  ```
  B = [15, 31, 63, 127, 255, 511, 1023, 2047]
  q = 4096
  r = 17
  ```
- Khóa bí mật:
  ```
  W = [1, 2, 4, 8, 16, 32, 64, 128]
  ```

### **Ký thông điệp**
- Thông điệp: `"Hello, this is a test message."`
- Chữ ký số: `S = 12345`.

### **Xác minh chữ ký**
- Kết quả: **Hợp lệ**.

---

## **Lưu ý**
- **Kích thước khóa**:
  - Giá trị tối thiểu: `4`.
  - Giá trị tối đa: `128`.
- **Bảo mật**:
  - Thuật toán MHK không an toàn cho các ứng dụng thực tế. Dự án này chỉ mang tính chất học thuật.

---

## **Tác giả**
- **Tên**: 
- **Email**: 
- **Dự án**: 

---