import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import random
import math
import os
import hashlib

# ==============================================================================
# == MHK Core Logic (Signature Scheme - Attempt 3) ===========================
# == (Backend functions remain identical) =====================================
# ==============================================================================

# --- Helper Functions --- (gcd, modInverse - same)
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

# --- Simplified Hashing --- (Same)
def get_hash_bits(message, num_bits, log_steps):
    log_steps.append(f"  Hashing message (SHA-256)...")
    hasher = hashlib.sha256(); hasher.update(message.encode('utf-8')); hash_bytes = hasher.digest()
    log_steps.append(f"    Full SHA-256 Hash (hex): {hash_bytes.hex()}")
    hash_int = int.from_bytes(hash_bytes, 'big')
    bits = []; mask = 1
    for i in range(num_bits): bits.append((hash_int & mask) >> i); mask <<= 1
    log_steps.append(f"  Using {num_bits}-bit simplified hash (LSBs): {bits}")
    return bits

# --- MHK Signature Core Functions (Scheme 3) --- (Same logic)
def generate_mhk_sig_keys_scheme3(key_size=8):
    log_steps = []; log_steps.append(f"\n--- Generating MHK Keys (Signature Scheme 3, size {key_size}) ---")
    w_private = [random.randint(2, 10)]; current_sum = w_private[0]
    for _ in range(1, key_size): next_val = current_sum + random.randint(1, 10); w_private.append(next_val); current_sum += next_val
    log_steps.append(f"[*] Private Superincreasing Sequence (W): {w_private}"); log_steps.append(f"    Sum(W) = {current_sum}")
    modulus_q = current_sum + random.randint(10, 100); log_steps.append(f"[*] Modulus (q): {modulus_q}")
    multiplier_r = random.randint(2, modulus_q - 1); inv = modInverse(multiplier_r, modulus_q)
    while inv is None: multiplier_r = random.randint(2, modulus_q - 1); inv = modInverse(multiplier_r, modulus_q)
    inverse_r_prime = inv
    log_steps.append(f"[*] Multiplier (r): {multiplier_r}"); log_steps.append(f"[*] Modular Inverse (r'): {inverse_r_prime} (Private component)")
    b_public = []; log_steps.append("[*] Calculating Public Key sequence (B):")
    for i, w_i in enumerate(w_private): b_i = (w_i * multiplier_r) % modulus_q; b_public.append(b_i); log_steps.append(f"    B[{i}] = ({w_i} * {multiplier_r}) mod {modulus_q} = {b_i}")
    public_key = (b_public, modulus_q, multiplier_r); private_key = (w_private, inverse_r_prime)
    log_steps.append(f"\n--- Key Generation Complete ---")
    return public_key, private_key, log_steps

def sign_mhk_scheme3(message, private_key_W_r_inv):
    log_steps = []; log_steps.append("\n--- Signing Message (Scheme 3) ---"); log_steps.append(f"Original Message: '{message[:50]}{'...' if len(message)>50 else ''}'")
    try: W, _ = private_key_W_r_inv; key_size = len(W); log_steps.append(f"Using Private Key (W): {W}")
    except Exception as e: log_steps.append(f"Error unpacking private key: {e}"); return None, log_steps
    h_bits = get_hash_bits(message, key_size, log_steps)
    if h_bits is None: return None, log_steps
    signature_s = 0; term_strings = []
    for i in range(key_size):
        term = h_bits[i] * W[i]; signature_s += term
        if h_bits[i] == 1: term_strings.append(f"{W[i]}")
    log_steps.append(f"  Calculating Signature S = sum(h_bit * W_i) = {' + '.join(term_strings)} = {signature_s}")
    log_steps.append("--- Signing Complete ---"); return signature_s, log_steps

def verify_mhk_scheme3(message, signature_s, public_key_B_q_r):
    log_steps = []; log_steps.append("\n--- Verifying Signature (Scheme 3) ---"); log_steps.append(f"Original Message: '{message[:50]}{'...' if len(message)>50 else ''}'"); log_steps.append(f"Signature S received: {signature_s}")
    try: B, q, r = public_key_B_q_r; key_size = len(B); log_steps.append(f"Using Public Key (B): {B}"); log_steps.append(f"Using Modulus (q): {q}"); log_steps.append(f"Using Multiplier (r): {r}")
    except Exception as e: log_steps.append(f"Error unpacking public key: {e}"); return False, log_steps
    h_bits = get_hash_bits(message, key_size, log_steps)
    if h_bits is None: return False, log_steps
    log_steps.append(f"  Expected hash bits: {h_bits}")
    lhs = (signature_s * r) % q; log_steps.append(f"  Calculating LHS = (S * r) mod q = ({signature_s} * {r}) mod {q} = {lhs}")
    rhs_unmod = 0; term_strings = []
    for i in range(key_size):
        term = h_bits[i] * B[i]; rhs_unmod += term
        if h_bits[i] == 1: term_strings.append(f"{B[i]}")
    rhs = rhs_unmod % q; log_steps.append(f"  Calculating RHS = (sum(h_bit * B_i)) mod q"); log_steps.append(f"    sum = {' + '.join(term_strings)} = {rhs_unmod}"); log_steps.append(f"    RHS = {rhs_unmod} mod {q} = {rhs}")
    is_match = (lhs == rhs)
    if is_match: log_steps.append(f"  Match! LHS ({lhs}) == RHS ({rhs})"); log_steps.append("--- Verification Successful ---"); return True, log_steps
    else: log_steps.append(f"  Mismatch! LHS ({lhs}) != RHS ({rhs})"); log_steps.append("--- Verification Failed ---"); return False, log_steps

# ==============================================================================
# == GUI Application Class (Themed) ==========================================
# ==============================================================================

class MHK_Signature_GUI_Scheme3:
    def __init__(self, master):
        self.master = master
        master.title("MHK Knapsack Signature Scheme (Minty)") # Updated title
        master.geometry("850x750")

        # --- Color Scheme ---
        BG_COLOR = "#F5F5DC"  # Off-white / Beige (like wheat or antique white)
        # BG_COLOR = "#D2B48C" # Light Brown / Tan
        BUTTON_COLOR = "#98FF98" # Mint Green (PaleGreen) or try #AFEEEE (PaleTurquoise)
        TEXT_COLOR = "#FF1493"   # FF69B4 Pink (HotPink) or try # (DeepPink)
        ENTRY_BG = "#FFFFFF" # White background for entry/text widgets usually looks ok
        ENTRY_FG = TEXT_COLOR # Use pink text in entries

        master.config(bg=BG_COLOR) # Set main window background

        # --- Store Keys ---
        self.public_key = None; self.private_key = None

        # --- Style ---
        style = ttk.Style()
        try:
            style.theme_use('clam') # 'clam' often allows more customization
        except tk.TclError:
            print("Theme 'clam' not available, using default.")
        # Configure Button style (background is main thing, foreground might not work)
        style.configure("TButton",
                padding=5,
                background=BUTTON_COLOR,
                foreground=TEXT_COLOR,
                font=('Arial', 10, 'bold'),
                borderwidth=1)
        # Map the style to actual buttons, needed sometimes for bg to apply
        style.map("TButton",
          # Ensure background stays mint when active (pressed)
          background=[('active', '#AAFFAA')], # Slightly darker mint on active
          # You might need to experiment with relief styles too
          relief=[('pressed', 'relief'), ('!pressed', 'raised')])

        # Configure Label style
        style.configure("TLabel", padding=3, background=BG_COLOR, foreground=TEXT_COLOR, font=('Arial', 10))
        # Configure LabelFrame title style
        style.configure("TLabelframe.Label", background=BG_COLOR, foreground=TEXT_COLOR, font=("Arial", 10, "bold"))
        # Configure LabelFrame border/background
        style.configure("TLabelframe", background=BG_COLOR)


        # --- Main Frame ---
        # Set background for the main frame as well
        main_frame = ttk.Frame(master, padding="10", style="TFrame") # Style might be needed for bg
        style.configure("TFrame", background=BG_COLOR) # Configure frame background
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Key Generation and Display Area ---
        key_frame = ttk.LabelFrame(main_frame, text="Keys", padding="10")
        key_frame.pack(fill=tk.X, pady=5)

        self.btn_gen_keys = ttk.Button(key_frame, text="Generate Keys", command=self.generate_keys_gui)
        self.btn_gen_keys.pack(side=tk.LEFT, padx=5)

        self.lbl_pub_key = ttk.Label(key_frame, text="Public Key (B):")
        self.lbl_pub_key.pack(fill=tk.X, pady=(5,0))
        # Use tk.Entry if ttk Entry styling is problematic, but ttk is preferred
        self.entry_pub_key_b = ttk.Entry(key_frame, width=90, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('Consolas', 9))
        self.entry_pub_key_b.pack(fill=tk.X, padx=5)

        pub_q_r_frame = ttk.Frame(key_frame, style="TFrame"); pub_q_r_frame.pack(fill=tk.X, pady=(2,5))
        self.lbl_pub_q = ttk.Label(pub_q_r_frame, text="Public (q):"); self.lbl_pub_q.pack(side=tk.LEFT, padx=(0, 5))
        self.entry_pub_q = ttk.Entry(pub_q_r_frame, width=15, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('Consolas', 9)); self.entry_pub_q.pack(side=tk.LEFT, padx=5)
        self.lbl_pub_r = ttk.Label(pub_q_r_frame, text="Public (r):"); self.lbl_pub_r.pack(side=tk.LEFT, padx=(20, 5))
        self.entry_pub_r = ttk.Entry(pub_q_r_frame, width=15, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('Consolas', 9)); self.entry_pub_r.pack(side=tk.LEFT, padx=5)

        self.lbl_priv_w = ttk.Label(key_frame, text="Private Key (W):"); self.lbl_priv_w.pack(fill=tk.X, pady=(5,0))
        self.entry_priv_w = ttk.Entry(key_frame, width=90, state='readonly', foreground=ENTRY_FG, background=ENTRY_BG, font=('Consolas', 9))
        self.entry_priv_w.pack(fill=tk.X, padx=5)


        # --- Message Input Area ---
        msg_frame = ttk.LabelFrame(main_frame, text="Message (M)", padding="10")
        msg_frame.pack(fill=tk.X, pady=5)
        # ScrolledText is tk based, need to configure directly
        self.txt_message = scrolledtext.ScrolledText(msg_frame, height=5, width=80, wrap=tk.WORD,
                                                     bg=ENTRY_BG, fg=ENTRY_FG, font=('Arial', 10))
        self.txt_message.pack(fill=tk.X, expand=True)
        self.btn_load_msg = ttk.Button(msg_frame, text="Load from File...", command=self.load_message_from_file)
        self.btn_load_msg.pack(side=tk.LEFT, pady=5, padx=5)

        # --- Signature Area ---
        sig_frame = ttk.LabelFrame(main_frame, text="Signature (S)", padding="10")
        sig_frame.pack(fill=tk.X, pady=5)
        self.entry_signature = ttk.Entry(sig_frame, width=80, foreground=ENTRY_FG, background=ENTRY_BG, font=('Consolas', 9))
        self.entry_signature.pack(fill=tk.X, expand=True)

        # --- Action Buttons Frame ---
        action_frame = ttk.Frame(main_frame, style="TFrame"); action_frame.pack(fill=tk.X, pady=5)
        self.btn_sign = ttk.Button(action_frame, text="Sign Message", command=self.sign_message_gui); self.btn_sign.pack(side=tk.LEFT, padx=10, pady=5, expand=True)
        self.btn_verify = ttk.Button(action_frame, text="Verify Signature", command=self.verify_signature_gui); self.btn_verify.pack(side=tk.LEFT, padx=10, pady=5, expand=True)
        self.btn_clear = ttk.Button(action_frame, text="Clear All", command=self.clear_fields); self.btn_clear.pack(side=tk.LEFT, padx=10, pady=5, expand=True)

        # --- Log/Status Area ---
        log_frame = ttk.LabelFrame(main_frame, text="Log / Intermediate Steps", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.txt_log = scrolledtext.ScrolledText(log_frame, height=12, width=80, wrap=tk.WORD, state=tk.DISABLED,
                                                 bg="#E0E0E0", fg="#333333", font=('Consolas', 9)) # Log uses different colors for readability
        self.txt_log.pack(fill=tk.BOTH, expand=True)

    # --- GUI Action Methods --- (Logic is the same, just calling log)

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
        # Special handling for readonly background if needed (ttk themes can be tricky)
        # entry_widget.config(state='readonly', readonlybackground=ENTRY_BG) # Maybe needed
        entry_widget.config(state='readonly')


    def generate_keys_gui(self):
        self.log("Initiating key generation (Scheme 3)...")
        try:
            pub_key, priv_key, key_log = generate_mhk_sig_keys_scheme3(key_size=8)
            for step in key_log: self.log(step)
            if pub_key and priv_key:
                self.public_key = pub_key; self.private_key = priv_key
                B, q, r = self.public_key; W, _ = self.private_key # Unpack
                self._set_entry_text(self.entry_pub_key_b, B); self._set_entry_text(self.entry_pub_q, q); self._set_entry_text(self.entry_pub_r, r)
                self._set_entry_text(self.entry_priv_w, W)
                self.log("Keys generated and displayed.")
                messagebox.showinfo("Keys Generated", "Public and Private keys generated successfully!")
            else:
                messagebox.showerror("Error", "Key generation failed. Check log.")
        except Exception as e: messagebox.showerror("Error", f"An error occurred during key generation:\n{e}"); self.log(f"ERROR in key generation: {e}")

    def load_message_from_file(self):
        self.log("Attempting to load message from file...")
        filepath = filedialog.askopenfilename(title="Open Message File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not filepath: self.log("File open cancelled."); return
        try:
            with open(filepath, 'r', encoding='utf-8') as f: content = f.read()
            self.txt_message.delete('1.0', tk.END); self.txt_message.insert('1.0', content)
            self.log(f"Loaded message from: {filepath}"); messagebox.showinfo("File Loaded", f"Successfully loaded message from:\n{filepath}")
        except Exception as e: messagebox.showerror("File Error", f"Could not read file:\n{e}"); self.log(f"Error loading file {filepath}: {e}")

    def sign_message_gui(self):
        if not self.private_key: messagebox.showerror("Error", "Please generate keys first."); return
        message = self.txt_message.get("1.0", tk.END).strip()
        if not message: messagebox.showwarning("Warning", "Message input is empty."); return
        self.log("\nInitiating signing (Scheme 3)...")
        try:
            signature_s, sign_log = sign_mhk_scheme3(message, self.private_key)
            for step in sign_log: self.log(step)
            if signature_s is not None:
                self.entry_signature.delete(0, tk.END); self.entry_signature.insert(0, str(signature_s))
                self.log("Signing successful. Signature displayed."); messagebox.showinfo("Signing Complete", f"Message signed successfully.\nSignature (S): {signature_s}")
            else: messagebox.showerror("Error", "Signing failed. Check log.")
        except Exception as e: messagebox.showerror("Error", f"An error occurred during signing:\n{e}"); self.log(f"ERROR during signing: {e}")

    def verify_signature_gui(self):
        if not self.public_key: messagebox.showerror("Error", "Please generate keys first."); return
        message = self.txt_message.get("1.0", tk.END).strip();
        if not message: messagebox.showwarning("Warning", "Message input is empty."); return
        signature_str = self.entry_signature.get().strip();
        if not signature_str: messagebox.showwarning("Warning", "Signature input is empty."); return
        try: signature_s = int(signature_str)
        except ValueError: messagebox.showerror("Error", "Invalid Signature format."); return
        self.log("\nInitiating verification (Scheme 3)...")
        try:
            is_valid, verify_log = verify_mhk_scheme3(message, signature_s, self.public_key)
            for step in verify_log: self.log(step)
            if is_valid: messagebox.showinfo("Verification Result", "Signature is VALID."); self.log(">>> Overall Verification Result: VALID <<<")
            else: messagebox.showwarning("Verification Result", "Signature is INVALID."); self.log(">>> Overall Verification Result: INVALID <<<")
        except Exception as e: messagebox.showerror("Error", f"An error occurred during verification:\n{e}"); self.log(f"ERROR during verification: {e}")

    def clear_fields(self):
        self.txt_message.delete('1.0', tk.END); self.entry_signature.delete(0, tk.END)
        self.txt_log.config(state=tk.NORMAL); self.txt_log.delete('1.0', tk.END); self.txt_log.config(state=tk.DISABLED)
        self._set_entry_text(self.entry_pub_key_b, ""); self._set_entry_text(self.entry_pub_q, ""); self._set_entry_text(self.entry_pub_r, "")
        self._set_entry_text(self.entry_priv_w, "")
        self.public_key = None; self.private_key = None
        self.log("Fields cleared and keys reset."); messagebox.showinfo("Cleared", "All fields and keys have been cleared.")

# ==============================================================================
# == Main Execution ============================================================
# ==============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = MHK_Signature_GUI_Scheme3(root)
    root.mainloop()