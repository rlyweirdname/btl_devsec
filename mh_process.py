import random
import math
import os  # Để kiểm tra đường dẫn file

# Hàm bổ trợ

def gcd(a, b):
    """Tính ƯCLN của a và b."""
    while b:
        a, b = b, a % b
    return a

def modInverse(a, m):
    """Tính toán nghịch đảo nhân môđun của a theo modulo m bằng Thuật toán Euclid mở rộng."""
    m0, x0, x1 = m, 0, 1
    a_orig = a
    if m == 1: return 0
    while a > 1:
        if m == 0: return None
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if a != 1: return None  # kiểm tra xem ƯCLN = 1
    if x1 < 0: x1 += m0
    return x1

def solve_knapsack_greedy(target, w):
    bits = [0] * len(w)
    remaining = target
    print(f"    Đang giải bài toán Knapsack với mục tiêu = {target}")
    for i in range(len(w) - 1, -1, -1):
        if remaining < 0 or w[i] <= 0:
            print(f"    Lỗi: còn lại={remaining}, w[{i}]={w[i]}")
            return None  # Trạng thái lỗi

        if remaining >= w[i]:
            bits[i] = 1
            print(f"      w[{i}] = {w[i]} <= {remaining}. Sử dụng. Bit[{i}]=1.")
            remaining -= w[i]
            print(f"      Còn lại = {remaining}")
        else:
            print(f"      w[{i}] = {w[i]} > {remaining}. Bỏ qua. Bit[{i}]=0.")

    if remaining != 0:
        print(f"    Giải bài toán Knapsack thất bại: Phần dư = {remaining} != 0")
        return None
    print(f"    Giải bài toán Knapsack thành công: Bits = {bits}")
    return bits

# Hàm chính của MHK

def generate_mhk_keys(key_size=8):
    print(f"\n--- Đang tạo khóa MHK (kích thước {key_size}) ---")
    w_private = []  # Dãy siêu tăng
    current_sum = 0
    w_private.append(random.randint(2, 10))
    current_sum = w_private[0]

    for _ in range(1, key_size):
        next_val = current_sum + random.randint(1, 10) 
        w_private.append(next_val)
        current_sum += next_val
    print(f"[*] Dãy siêu tăng bí mật (W): {w_private}")
    print(f"    Tổng(W) = {current_sum}")

    modulus_q = current_sum + random.randint(10, 100)
    print(f"[*] Môđun (q): {modulus_q}")

    multiplier_r = random.randint(2, modulus_q - 1)
    inv = modInverse(multiplier_r, modulus_q)
    while inv is None: 
        multiplier_r = random.randint(2, modulus_q - 1)
        inv = modInverse(multiplier_r, modulus_q)
    inverse_r_prime = inv
    print(f"[*] Số nhân (r): {multiplier_r}")
    print(f"[*] Nghịch đảo môđun (r'): {inverse_r_prime}") 

    b_public = []
    print("[*] Đang tính toán khóa công khai (B):")
    for i, w_i in enumerate(w_private):
        b_i = (w_i * multiplier_r) % modulus_q
        b_public.append(b_i)
        print(f"    B[{i}] = ({w_i} * {multiplier_r}) mod {modulus_q} = {b_i}")

    public_key_B = b_public
    private_key_W_q_r_inv = (w_private, modulus_q, inverse_r_prime)

    print(f"\n--- Tạo khóa hoàn tất ---")
    print(f"Khóa công khai (B): {public_key_B}")
    print(f"Khóa bí mật (W, q, r'): {private_key_W_q_r_inv}")
    return public_key_B, private_key_W_q_r_inv

def encrypt_mhk(message, public_key_B):
    """Mã hóa một chuỗi thông điệp bằng khóa công khai MHK B."""
    print("\n--- Đang mã hóa thông điệp ---")
    print(f"Thông điệp gốc: '{message}'")
    print(f"Sử dụng khóa công khai (B): {public_key_B}")
    key_size = len(public_key_B)
    ciphertext_list = []

    try:
        message_bytes = message.encode('utf-8')
        print(f"Thông điệp dưới dạng bytes: {message_bytes}")
    except Exception as e:
        print(f"Lỗi khi mã hóa thông điệp thành bytes: {e}")
        return None

    print("\nXử lý các khối:")
    block_num = 0
    for byte_val in message_bytes:
        block_num += 1
        print(f"  Khối {block_num} (Giá trị byte: {byte_val}):")
        try:
            bits_str = format(byte_val, f'0{key_size}b')
            bits = [int(bit) for bit in bits_str]
            print(f"    Bits (x): {bits_str} -> {bits}")
        except Exception as e:
            print(f"    Lỗi khi chuyển byte {byte_val} thành bits: {e}")
            continue 

        c = 0
        term_strings = []
        for i in range(key_size):
            term = bits[i] * public_key_B[i]
            c += term
            if bits[i] == 1:
                term_strings.append(f"{public_key_B[i]}")
        print(f"    Tính toán c = sum(x_i * B_i) = {' + '.join(term_strings)} = {c}")
        ciphertext_list.append(c)

    print("\n--- Mã hóa hoàn tất ---")
    print(f"Bản mã (danh sách số nguyên): {ciphertext_list}")
    return ciphertext_list

def decrypt_mhk(ciphertext_list, private_key_W_q_r_inv):
    print("\n--- Đang giải mã thông điệp ---")
    print(f"Danh sách bản mã nhận được: {ciphertext_list}")
    try:
        W, q, r_prime = private_key_W_q_r_inv
        key_size = len(W)
        print(f"Sử dụng khóa bí mật (W): {W}")
        print(f"Sử dụng modulo (q): {q}")
        print(f"Sử dụng nghịch đảo (r'): {r_prime}")
    except Exception as e:
        print(f"Lỗi khi giải nén khóa bí mật: {e}")
        return None

    decrypted_bytes_list = []
    print("\nXử lý các khối:")
    block_num = 0
    for c in ciphertext_list:
        block_num += 1
        print(f"  Khối {block_num} (Bản mã c = {c}):")

        c_prime = (c * r_prime) % q
        print(f"    Tính toán c' = (c * r') mod q = ({c} * {r_prime}) mod {q} = {c_prime}")

        decrypted_bits = solve_knapsack_greedy(c_prime, W)

        if decrypted_bits is None:
            print(f"    LỖI: Không thể giải mã khối {block_num}. Bỏ qua.")
            decrypted_bytes_list.append(0)
            continue

 
        byte_val = 0
        power_of_2 = 1
        for bit in reversed(decrypted_bits):
            if bit == 1:
                byte_val += power_of_2
            power_of_2 *= 2
        print(f"    Các bits khôi phục {decrypted_bits} tương ứng với giá trị byte: {byte_val}")
        decrypted_bytes_list.append(byte_val)

    try:
        decrypted_message = bytes(decrypted_bytes_list).decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Lỗi khi giải mã bytes thành chuỗi: {e}")
        decrypted_message = "[Lỗi giải mã]"

    print("\n--- Giải mã hoàn tất ---")
    print(f"Thông điệp đã giải mã: '{decrypted_message}'")
    return decrypted_message

# Main
if __name__ == "__main__":
    # Tạo khóa
    publicKey, privateKey = generate_mhk_keys(key_size=8)

    if publicKey is None or privateKey is None:
        print("\nTạo khóa thất bại. Thoát.")
        exit()

    print("*" * 60)

    message_input = input("Nhập thông điệp để mã hóa HOẶC đường dẫn đến file: ")
    message_to_encrypt = "\n"
    is_file = os.path.isfile(message_input)

    if is_file:
        print(f"\nĐang đọc thông điệp từ file: {message_input}")
        try:
            with open(message_input, 'r', encoding='utf-8') as f:
                message_to_encrypt = f.read()
            print("...Đọc file thành công.")
        except Exception as e:
            print(f"Lỗi khi đọc file: {e}")
            exit()
    else:
        print("\nSử dụng thông điệp trực tiếp.")
        message_to_encrypt = message_input

    if not message_to_encrypt:
        print("Lỗi: Không có thông điệp được cung cấp.")
        exit()

    print("*" * 60)

    encrypted_data = encrypt_mhk(message_to_encrypt, publicKey)

    print("*" * 60)

    if encrypted_data is not None:
        decrypted_result = decrypt_mhk(encrypted_data, privateKey)

        print("*" * 60)

        print("\n--- Xác minh bước cuối cùng ---")
        if decrypted_result == message_to_encrypt:
            print("THÀNH CÔNG: Thông điệp đã giải mã KHỚP với đầu vào ban đầu.")
        else:
            print("THẤT BẠI: Thông điệp đã giải mã KHÔNG KHỚP với đầu vào ban đầu.")
            print(f"Gốc:  '{message_to_encrypt}'")
            print(f"Đã giải mã: '{decrypted_result}'")
        print("*" * 60)
    else:
        print("\nMã hóa thất bại, bỏ qua giải mã.")
        print("*" * 60)