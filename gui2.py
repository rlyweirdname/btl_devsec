import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import random
import math
import os
import hashlib


def gcd(a, b):
    while b: a, b = b, a % b
    return a

def modInverse(a, m):
    m0, x0, x1 = m, 0, 1; a_orig = a
    if m == 1: return 0
    while a > 1:
        if m == 0: return None
        q = a // m; m, a = a % m, m; x0, x1 = x1 - q * x0, x0
    if a != 1: return None
    if x1 < 0: x1 += m0
    return x1

def get_hash_bits(message, num_bits, log_steps):
    log_steps.append(f"  Băm thông điệp (SHA-256)...")
    hasher = hashlib.sha256(); hasher.update(message.encode('utf-8')); hash_bytes = hasher.digest()
    log_steps.append(f"    Băm SHA-256 đầy đủ (hex): {hash_bytes.hex()}")
    hash_int = int.from_bytes(hash_bytes, 'big')
    bits = []; mask = 1
    for i in range(num_bits): bits.append((hash_int & mask) >> i); mask <<= 1
    log_steps.append(f"  Sử dụng {num_bits}-bit băm đơn giản (LSBs): {bits}")
    return bits

def generate_mhk_sig_keys_scheme3(key_size=8):
    log_steps = []; log_steps.append(f"\n--- Đang tạo khóa MHK (Kích thước {key_size}) ---")
    w_private = [random.randint(2, 10)]; current_sum = w_private[0]
    for _ in range(1, key_size): next_val = current_sum + random.randint(1, 10); w_private.append(next_val); current_sum += next_val
    log_steps.append(f"[*] Dãy siêu tăng bí mật (W): {w_private}"); log_steps.append(f"    Tổng(W) = {current_sum}")
    modulus_q = current_sum + random.randint(10, 100); log_steps.append(f"[*] Modulo (q): {modulus_q}")
    multiplier_r = random.randint(2, modulus_q - 1); inv = modInverse(multiplier_r, modulus_q)
    while inv is None: multiplier_r = random.randint(2, modulus_q - 1); inv = modInverse(multiplier_r, modulus_q)
    inverse_r_prime = inv
    log_steps.append(f"[*] Số nhân (r): {multiplier_r}"); log_steps.append(f"[*] Nghịch đảo modulo (r'): {inverse_r_prime}")
    b_public = []; log_steps.append("[*] Đang tính toán khóa công khai (B):")
    for i, w_i in enumerate(w_private): b_i = (w_i * multiplier_r) % modulus_q; b_public.append(b_i); log_steps.append(f"    B[{i}] = ({w_i} * {multiplier_r}) mod {modulus_q} = {b_i}")
    public_key = (b_public, modulus_q, multiplier_r); private_key = (w_private, inverse_r_prime)
    log_steps.append(f"\n--- Tạo khóa hoàn tất ---")
    return public_key, private_key, log_steps

def sign_mhk_scheme3(message, private_key_W_r_inv):
    log_steps = []; log_steps.append("\n--- Đang ký thông điệp ---"); log_steps.append(f"Thông điệp gốc: '{message[:50]}{'...' if len(message)>50 else ''}'")
    try: W, _ = private_key_W_r_inv; key_size = len(W); log_steps.append(f"Sử dụng khóa bí mật (W): {W}")
    except Exception as e: log_steps.append(f"Lỗi khi giải nén khóa bí mật: {e}"); return None, log_steps
    h_bits = get_hash_bits(message, key_size, log_steps)
    if h_bits is None: return None, log_steps
    signature_s = 0; term_strings = []
    for i in range(key_size):
        term = h_bits[i] * W[i]; signature_s += term
        if h_bits[i] == 1: term_strings.append(f"{W[i]}")
    log_steps.append(f"  Tính chữ ký S = sum(h_bit * W_i) = {' + '.join(term_strings)} = {signature_s}")
    log_steps.append("--- Ký hoàn tất ---"); return signature_s, log_steps

def verify_mhk_scheme3(message, signature_s, public_key_B_q_r):
    log_steps = []; log_steps.append("\n--- Đang xác minh chữ ký ---"); log_steps.append(f"Thông điệp gốc: '{message[:50]}{'...' if len(message)>50 else ''}'"); log_steps.append(f"Chữ ký S nhận được: {signature_s}")
    try: B, q, r = public_key_B_q_r; key_size = len(B); log_steps.append(f"Sử dụng khóa công khai (B): {B}"); log_steps.append(f"Sử dụng modulo (q): {q}"); log_steps.append(f"Sử dụng số nhân (r): {r}")
    except Exception as e: log_steps.append(f"Lỗi khi giải nén khóa công khai: {e}"); return False, log_steps
    h_bits = get_hash_bits(message, key_size, log_steps)
    if h_bits is None: return False, log_steps
    log_steps.append(f"  Các bit băm mong đợi: {h_bits}")
    lhs = (signature_s * r) % q; log_steps.append(f"  Tính LHS = (S * r) mod q = ({signature_s} * {r}) mod {q} = {lhs}")
    rhs_unmod = 0; term_strings = []
    for i in range(key_size):
        term = h_bits[i] * B[i]; rhs_unmod += term
        if h_bits[i] == 1: term_strings.append(f"{B[i]}")
    rhs = rhs_unmod % q; log_steps.append(f"  Tính RHS = (sum(h_bit * B_i)) mod q"); log_steps.append(f"    sum = {' + '.join(term_strings)} = {rhs_unmod}"); log_steps.append(f"    RHS = {rhs_unmod} mod {q} = {rhs}")
    is_match = (lhs == rhs)
    if is_match: log_steps.append(f"  Khớp! LHS ({lhs}) == RHS ({rhs})"); log_steps.append("--- Xác minh thành công ---"); return True, log_steps
    else: log_steps.append(f"  Không khớp! LHS ({lhs}) != RHS ({rhs})"); log_steps.append("--- Xác minh thất bại ---"); return False, log_steps



class MHK_Signature_GUI_Scheme3:
    def __init__(self, master):
        self.master = master
        master.title("Phần mềm chữ ký số MHK")
        master.geometry("850x750")

        #color
        BG_COLOR = "#faedcd" 
        BUTTON_COLOR = "#e9edc9"
        TEXT_COLOR = "#d4a373"
        ENTRY_BG = "#fefae0" 
        ENTRY_FG = TEXT_COLOR
         

        master.config(bg=BG_COLOR) 

        #lưu trữ khóa
        self.public_key = None; self.private_key = None

        #ttk style
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except tk.TclError:
            print("Theme 'clam' không khả dụng, sử dụng mặc định.")
        
        style.configure("TButton",
                padding=5,
                background=BUTTON_COLOR,
                foreground=TEXT_COLOR,
                font=('Helvetica', 10, 'bold'),
                borderwidth=1)
        
        style.map("TButton",
          background=[('active', '#cdeac0')], 
          relief=[('pressed', 'sunken'), ('!pressed', 'raised')])

        #Label style
        style.configure("TLabel", padding=3, background=BG_COLOR, foreground=TEXT_COLOR, font=('Helvetica', 10))
        #LabelFrame title style
        style.configure("TLabelframe.Label", background=BG_COLOR, foreground=TEXT_COLOR, font=("Helvetica", 10, "bold"))
        #LabelFrame border/background
        style.configure("TLabelframe", background=BG_COLOR)


        #Main Frame
        main_frame = ttk.Frame(master, padding="10", style="TFrame")
        style.configure("TFrame", background=BG_COLOR) 
        main_frame.pack(fill=tk.BOTH, expand=True)

        #key gen và display area
        key_frame = ttk.LabelFrame(main_frame, text="Khóa", padding="10")
        key_frame.pack(fill=tk.X, pady=5)

        self.btn_gen_keys = ttk.Button(key_frame, text="Tạo khóa", command=self.generate_keys_gui)
        self.btn_gen_keys.pack(side=tk.LEFT, padx=5)

        # Key size input
        key_size_frame = ttk.Frame(key_frame, style="TFrame")
        key_size_frame.pack(fill=tk.X, pady=(5, 5))

        self.lbl_key_size = ttk.Label(key_size_frame, text="Kích thước khóa:")
        self.lbl_key_size.pack(side=tk.LEFT, padx=(0, 5))

        self.entry_key_size = ttk.Entry(key_size_frame, width=10, foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9))
        self.entry_key_size.insert(0, "8") 
        self.entry_key_size.pack(side=tk.LEFT, padx=5)

        self.lbl_pub_key = ttk.Label(key_frame, text="Khóa công khai (B):")
        self.lbl_pub_key.pack(fill=tk.X, pady=(5,0))

        self.entry_pub_key_b = ttk.Entry(key_frame, width=90, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9))
        self.entry_pub_key_b.pack(fill=tk.X, padx=5)

        pub_q_r_frame = ttk.Frame(key_frame, style="TFrame"); pub_q_r_frame.pack(fill=tk.X, pady=(2,5))
        self.lbl_pub_q = ttk.Label(pub_q_r_frame, text="Modulo (q):"); self.lbl_pub_q.pack(side=tk.LEFT, padx=(0, 5))
        self.entry_pub_q = ttk.Entry(pub_q_r_frame, width=15, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9)); self.entry_pub_q.pack(side=tk.LEFT, padx=5)
        self.lbl_pub_r = ttk.Label(pub_q_r_frame, text="Hệ số nhân (r):"); self.lbl_pub_r.pack(side=tk.LEFT, padx=(20, 5))
        self.entry_pub_r = ttk.Entry(pub_q_r_frame, width=15, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9)); self.entry_pub_r.pack(side=tk.LEFT, padx=5)

        self.lbl_priv_w = ttk.Label(key_frame, text="Khóa bí mật (W):"); self.lbl_priv_w.pack(fill=tk.X, pady=(5,0))
        self.entry_priv_w = ttk.Entry(key_frame, width=90, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9))
        self.entry_priv_w.pack(fill=tk.X, padx=5)


        #input area
        msg_frame = ttk.LabelFrame(main_frame, text="Thông điệp (M)", padding="10")
        msg_frame.pack(fill=tk.X, pady=5)

        self.txt_message = scrolledtext.ScrolledText(msg_frame, height=5, width=80, wrap=tk.WORD,
                                                     bg=ENTRY_BG, fg=ENTRY_FG, font=('Helvetica', 10))
        self.txt_message.pack(fill=tk.X, expand=True)
        self.btn_load_msg = ttk.Button(msg_frame, text="Tải từ tệp...", command=self.load_message_from_file)
        self.btn_load_msg.pack(side=tk.LEFT, pady=5, padx=5)

        #signature area
        sig_frame = ttk.LabelFrame(main_frame, text="Chữ ký (S)", padding="10")
        sig_frame.pack(fill=tk.X, pady=5)
        self.entry_signature = ttk.Entry(sig_frame, width=80, foreground=ENTRY_FG, background=ENTRY_BG, font=('HelvLight', 9))
        self.entry_signature.pack(fill=tk.X, expand=True)

        #button frame
        action_frame = ttk.Frame(main_frame, style="TFrame"); action_frame.pack(fill=tk.X, pady=5)
        self.btn_sign = ttk.Button(action_frame, text="Ký thông điệp", command=self.sign_message_gui); self.btn_sign.pack(side=tk.LEFT, padx=10, pady=5, expand=True)
        self.btn_verify = ttk.Button(action_frame, text="Xác minh chữ ký", command=self.verify_signature_gui); self.btn_verify.pack(side=tk.LEFT, padx=10, pady=5, expand=True)
        self.btn_clear = ttk.Button(action_frame, text="Xóa tất cả", command=self.clear_fields); self.btn_clear.pack(side=tk.LEFT, padx=10, pady=5, expand=True)

        #log/status
        log_frame = ttk.LabelFrame(main_frame, text="Nhật ký / Các bước trung gian", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_log = scrolledtext.ScrolledText(log_frame, height=12, width=80, wrap=tk.WORD, state=tk.DISABLED,
                                                 bg="#E0E0E0", fg="#333333", font=('Consolas', 9))
        self.txt_log.pack(fill=tk.BOTH, expand=True)

    #GUI action menthod

    def log(self, message):
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.insert(tk.END, str(message) + "\n")
        self.txt_log.see(tk.END)
        self.txt_log.config(state=tk.DISABLED)
        self.master.update_idletasks()

    def _set_entry_text(self, entry_widget, text):
        entry_widget.config(state='normal')
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, str(text))
        # entry_widget.config(state='readonly', readonlybackground=ENTRY_BG) #có thể cần
        entry_widget.config(state='readonly')


    def generate_keys_gui(self):
        self.log("Bắt đầu tạo khóa...")
        try:
            key_size_str = self.entry_key_size.get().strip()
            if not key_size_str.isdigit():
                messagebox.showwarning("Cảnh báo", "Kích thước khóa không hợp lệ. Sử dụng giá trị mặc định (8).")
                key_size = 8
            else:
                key_size = int(key_size_str)
                if key_size < 4:
                    messagebox.showwarning("Cảnh báo", "Kích thước khóa quá nhỏ. Sử dụng giá trị tối thiểu (4).")
                    key_size = 4
                elif key_size > 128:
                    messagebox.showwarning("Cảnh báo", "Kích thước khóa quá lớn. Sử dụng giá trị tối đa (128).")
                    key_size = 128

            pub_key, priv_key, key_log = generate_mhk_sig_keys_scheme3(key_size=key_size)
            for step in key_log:
                self.log(step)
            if pub_key and priv_key:
                self.public_key = pub_key
                self.private_key = priv_key
                B, q, r = self.public_key
                W, _ = self.private_key
                self._set_entry_text(self.entry_pub_key_b, B)
                self._set_entry_text(self.entry_pub_q, q)
                self._set_entry_text(self.entry_pub_r, r)
                self._set_entry_text(self.entry_priv_w, W)
                self.log("Khóa đã được tạo và hiển thị.")
                messagebox.showinfo("Khóa đã tạo", "Khóa công khai và khóa bí mật đã được tạo thành công!")
            else:
                messagebox.showerror("Lỗi", "Tạo khóa thất bại. Kiểm tra nhật ký.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình tạo khóa:\n{e}")
            self.log(f"LỖI trong quá trình tạo khóa: {e}")

    def load_message_from_file(self):
        self.log("Đang cố gắng tải thông điệp từ tệp...")
        filepath = filedialog.askopenfilename(title="Mở tệp thông điệp", filetypes=[("Tệp văn bản", "*.txt"), ("Tất cả các tệp", "*.*")])
        if not filepath:
            self.log("Hủy mở tệp.")
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.txt_message.delete('1.0', tk.END)
            self.txt_message.insert('1.0', content)
            self.log(f"Đã tải thông điệp từ: {filepath}")
            messagebox.showinfo("Tệp đã tải", f"Đã tải thông điệp thành công từ:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Lỗi tệp", f"Không thể đọc tệp:\n{e}")
            self.log(f"Lỗi khi tải tệp {filepath}: {e}")

    def sign_message_gui(self):
        if not self.private_key:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa trước.")
            return
        message = self.txt_message.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Cảnh báo", "Thông điệp trống.")
            return
        self.log("\nBắt đầu ký thông điệp...")
        try:
            signature_s, sign_log = sign_mhk_scheme3(message, self.private_key)
            for step in sign_log:
                self.log(step)
            if signature_s is not None:
                self.entry_signature.delete(0, tk.END)
                self.entry_signature.insert(0, str(signature_s))
                self.log("Ký thành công. Chữ ký đã hiển thị.")
                messagebox.showinfo("Hoàn tất ký", f"Ký thông điệp thành công.\nChữ ký (S): {signature_s}")
            else:
                messagebox.showerror("Lỗi", "Ký thất bại. Kiểm tra nhật ký.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình ký:\n{e}")
            self.log(f"LỖI trong quá trình ký: {e}")

    def verify_signature_gui(self):
        if not self.public_key:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa trước.")
            return
        message = self.txt_message.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Cảnh báo", "Thông điệp trống.")
            return
        signature_str = self.entry_signature.get().strip()
        if not signature_str:
            messagebox.showwarning("Cảnh báo", "Chữ ký trống.")
            return
        try:
            signature_s = int(signature_str)
        except ValueError:
            messagebox.showerror("Lỗi", "Định dạng chữ ký không hợp lệ.")
            return
        self.log("\nBắt đầu xác minh chữ ký...")
        try:
            is_valid, verify_log = verify_mhk_scheme3(message, signature_s, self.public_key)
            for step in verify_log:
                self.log(step)
            if is_valid:
                messagebox.showinfo("Kết quả xác minh", "Chữ ký HỢP LỆ.")
                self.log(">>> Kết quả xác minh: HỢP LỆ <<<")
            else:
                messagebox.showwarning("Kết quả xác minh", "Chữ ký KHÔNG HỢP LỆ.")
                self.log(">>> Kết quả xác minh: KHÔNG HỢP LỆ <<<")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình xác minh:\n{e}")
            self.log(f"LỖI trong quá trình xác minh: {e}")

    def clear_fields(self):
        self.txt_message.delete('1.0', tk.END)
        self.entry_signature.delete(0, tk.END)
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.delete('1.0', tk.END)
        self.txt_log.config(state=tk.DISABLED)
        self._set_entry_text(self.entry_pub_key_b, "")
        self._set_entry_text(self.entry_pub_q, "")
        self._set_entry_text(self.entry_pub_r, "")
        self._set_entry_text(self.entry_priv_w, "")
        self.public_key = None
        self.private_key = None
        self.log("Đã xóa tất cả các trường và đặt lại khóa.")
        messagebox.showinfo("Đã xóa", "Tất cả các trường và khóa đã được xóa.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MHK_Signature_GUI_Scheme3(root)
    root.mainloop()