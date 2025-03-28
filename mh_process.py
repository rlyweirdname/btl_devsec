import random
import math
import os # To check for file paths

# --- Helper Functions ---

def gcd(a, b):
    """Compute the greatest common divisor of a and b"""
    while b:
        a, b = b, a % b
    return a

def modInverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m using Extended Euclidean Algorithm."""
    m0, x0, x1 = m, 0, 1
    a_orig = a
    if m == 1: return 0
    while a > 1:
        if m == 0: return None
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if a != 1: return None # Check if gcd was 1
    if x1 < 0: x1 += m0
    return x1

def solve_knapsack_greedy(target, w):
    """
    Solves the superincreasing knapsack problem using the greedy algorithm.
    Returns the list of bits [0, 1, ..., 1] corresponding to w, or None if no exact solution.
    """
    bits = [0] * len(w)
    remaining = target
    print(f"    Solving Knapsack for target = {target}")
    for i in range(len(w) - 1, -1, -1):
        if remaining < 0 or w[i] <= 0:
             print(f"    Error state: remaining={remaining}, w[{i}]={w[i]}")
             return None # Error state

        if remaining >= w[i]:
            bits[i] = 1
            print(f"      w[{i}] = {w[i]} <= {remaining}. Use it. Bit[{i}]=1.")
            remaining -= w[i]
            print(f"      Remaining = {remaining}")
        else:
            print(f"      w[{i}] = {w[i]} > {remaining}. Skip it. Bit[{i}]=0.")

    if remaining != 0:
        print(f"    Knapsack solution failed: Remainder = {remaining} != 0")
        return None
    print(f"    Knapsack solution found: Bits = {bits}")
    return bits

# --- MHK Core Functions ---

def generate_mhk_keys(key_size=8):
    """
    Generates Merkle-Hellman private and public keys.
    Returns: (public_key_B, private_key_W_q_r_inv) or (None, None) on failure.
    """
    print(f"\n--- Generating MHK Keys (size {key_size}) ---")
    w_private = [] # Superincreasing sequence
    current_sum = 0
    # Ensure the first element isn't too small relative to potential later sums
    w_private.append(random.randint(2, 10))
    current_sum = w_private[0]

    for _ in range(1, key_size):
        next_val = current_sum + random.randint(1, 10) # Smaller random additions common in examples
        w_private.append(next_val)
        current_sum += next_val
    print(f"[*] Private Superincreasing Sequence (W): {w_private}")
    print(f"    Sum(W) = {current_sum}")

    # Choose modulus q > sum(W)
    modulus_q = current_sum + random.randint(10, 100) # Add a margin
    print(f"[*] Modulus (q): {modulus_q}")

    # Choose multiplier r such that 1 < r < q and gcd(r, q) == 1
    multiplier_r = random.randint(2, modulus_q - 1)
    inv = modInverse(multiplier_r, modulus_q)
    while inv is None: # Ensure r has an inverse mod q
        multiplier_r = random.randint(2, modulus_q - 1)
        inv = modInverse(multiplier_r, modulus_q)
    inverse_r_prime = inv
    print(f"[*] Multiplier (r): {multiplier_r}")
    print(f"[*] Modular Inverse (r'): {inverse_r_prime}") # r' is part of private key

    # Calculate Public Key sequence B
    b_public = []
    print("[*] Calculating Public Key (B):")
    for i, w_i in enumerate(w_private):
        b_i = (w_i * multiplier_r) % modulus_q
        b_public.append(b_i)
        print(f"    B[{i}] = ({w_i} * {multiplier_r}) mod {modulus_q} = {b_i}")

    # Define return keys
    public_key_B = b_public # Just the sequence B
    private_key_W_q_r_inv = (w_private, modulus_q, inverse_r_prime)

    print(f"\n--- Key Generation Complete ---")
    print(f"Public Key (B): {public_key_B}")
    print(f"Private Key (W, q, r'): {private_key_W_q_r_inv}") # Keep W, q, r' secret
    return public_key_B, private_key_W_q_r_inv

def encrypt_mhk(message, public_key_B):
    """Encrypts a string message using the MHK public key B."""
    print("\n--- Encrypting Message ---")
    print(f"Original Message: '{message}'")
    print(f"Using Public Key (B): {public_key_B}")
    key_size = len(public_key_B)
    ciphertext_list = []

    try:
        message_bytes = message.encode('utf-8')
        print(f"Message as bytes: {message_bytes}")
    except Exception as e:
        print(f"Error encoding message to bytes: {e}")
        return None

    print("\nProcessing blocks:")
    block_num = 0
    for byte_val in message_bytes:
        block_num += 1
        print(f"  Block {block_num} (Byte Value: {byte_val}):")
        try:
            # Convert byte to binary string (e.g., '01100001')
            bits_str = format(byte_val, f'0{key_size}b')
            # Convert to list of ints [0, 1, 1, ...]
            bits = [int(bit) for bit in bits_str]
            print(f"    Bits (x): {bits_str} -> {bits}")
        except Exception as e:
            print(f"    Error converting byte {byte_val} to bits: {e}")
            continue # Skip this block

        # Calculate Ciphertext c = sum(x_i * B_i)
        c = 0
        term_strings = []
        for i in range(key_size):
            term = bits[i] * public_key_B[i]
            c += term
            if bits[i] == 1: # Only show terms that contribute
                 term_strings.append(f"{public_key_B[i]}")
        print(f"    Calculating c = sum(x_i * B_i) = {' + '.join(term_strings)} = {c}")
        ciphertext_list.append(c)

    print("\n--- Encryption Complete ---")
    print(f"Ciphertext (list of integers): {ciphertext_list}")
    return ciphertext_list


def decrypt_mhk(ciphertext_list, private_key_W_q_r_inv):
    """Decrypts a list of MHK ciphertext integers using the private key."""
    print("\n--- Decrypting Message ---")
    print(f"Received Ciphertext List: {ciphertext_list}")
    try:
        W, q, r_prime = private_key_W_q_r_inv
        key_size = len(W)
        print(f"Using Private Key (W): {W}")
        print(f"Using Modulus (q): {q}")
        print(f"Using Inverse (r'): {r_prime}")
    except Exception as e:
        print(f"Error unpacking private key: {e}")
        return None

    decrypted_bytes_list = []
    print("\nProcessing blocks:")
    block_num = 0
    for c in ciphertext_list:
        block_num += 1
        print(f"  Block {block_num} (Ciphertext c = {c}):")

        # Calculate c' = c * r' mod q
        c_prime = (c * r_prime) % q
        print(f"    Calculating c' = (c * r') mod q = ({c} * {r_prime}) mod {q} = {c_prime}")

        # Solve the easy knapsack for c' using W
        decrypted_bits = solve_knapsack_greedy(c_prime, W)

        if decrypted_bits is None:
            print(f"    ERROR: Failed to decrypt block {block_num}. Skipping.")
            # Represent error/skip, maybe with a placeholder byte value?
            # Using 0 here, but could use None or raise an error.
            decrypted_bytes_list.append(0) # Or handle error differently
            continue

        # Convert recovered bits back to integer/byte value
        byte_val = 0
        power_of_2 = 1
        for bit in reversed(decrypted_bits): # Process LSB first
            if bit == 1:
                byte_val += power_of_2
            power_of_2 *= 2
        print(f"    Recovered Bits {decrypted_bits} correspond to Byte Value: {byte_val}")
        decrypted_bytes_list.append(byte_val)

    # Combine bytes back into a string
    try:
        decrypted_message = bytes(decrypted_bytes_list).decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error decoding final bytes to string: {e}")
        decrypted_message = "[Decoding Error]"

    print("\n--- Decryption Complete ---")
    print(f"Decrypted Message: '{decrypted_message}'")
    return decrypted_message


# --- Main Execution ---
if __name__ == "__main__":
    print("*"*60)
    print(" Merkle-Hellman Knapsack Cryptosystem (Encryption/Decryption)")
    print(" (Based on standard algorithm - Educational Purposes Only)")
    print("*"*60)

    # Generate Keys
    publicKey, privateKey = generate_mhk_keys(key_size=8)

    if publicKey is None or privateKey is None:
        print("\nKey generation failed. Exiting.")
        exit()

    print("*"*60)

    # Get Message Input
    message_input = input("Enter the message to encrypt OR the path to a file: ")
    message_to_encrypt = ""
    is_file = os.path.isfile(message_input)

    if is_file:
        print(f"\nReading message from file: {message_input}")
        try:
            with open(message_input, 'r', encoding='utf-8') as f:
                message_to_encrypt = f.read()
            print("...File read successfully.")
        except Exception as e:
            print(f"Error reading file: {e}")
            exit()
    else:
        print("\nUsing direct input as message.")
        message_to_encrypt = message_input

    if not message_to_encrypt:
         print("Error: No message provided.")
         exit()

    print("*"*60)

    # Encrypt
    encrypted_data = encrypt_mhk(message_to_encrypt, publicKey)

    print("*"*60)

    # Decrypt
    if encrypted_data is not None:
        decrypted_result = decrypt_mhk(encrypted_data, privateKey)

        print("*"*60)
        # Final comparison
        print("\n--- Final Verification ---")
        if decrypted_result == message_to_encrypt:
             print("SUCCESS: Decrypted message matches the original input.")
        else:
             print("FAILURE: Decrypted message does NOT match the original input.")
             print(f"Original:  '{message_to_encrypt}'")
             print(f"Decrypted: '{decrypted_result}'")
        print("*"*60)
    else:
        print("\nEncryption failed, skipping decryption.")
        print("*"*60)