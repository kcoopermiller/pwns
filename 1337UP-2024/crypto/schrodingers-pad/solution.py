import socket

def reverse_cat_box_alive(ciphertext):
    c = bytearray(ciphertext)
    for i in range(len(c)):
        c[i] ^= 0xAC
        c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
    return bytes(c)

def reverse_cat_box_dead(ciphertext):
    c = bytearray(ciphertext)
    for i in range(len(c)):
        c[i] ^= 0xCA
        c[i] = ((c[i] << 1) | (c[i] >> 7)) & 0xFF
    return bytes(c)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def solve_challenge():
    HOST = 'pad.ctf.intigriti.io'
    PORT = 1348    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    # Read all initial messages
    data = b""
    while True:
        chunk = sock.recv(1024)
        data += chunk
        if b"try it for yourself?" in data:
            break
    
    # Convert to string and split messages
    messages = data.decode('utf-8', errors='ignore')
    print("All server messages received:", messages)
    
    # Extract the encrypted flag
    for line in messages.split('\n'):
        if "Encrypted (cat state=ERROR!" in line:
            flag_cipher_hex = line.split(': ')[1].split('\n')[0].strip()
            break
    
    print("\nExtracted flag cipher (hex):", flag_cipher_hex)
    
    # Decode the flag cipher
    flag_cipher = bytes.fromhex(flag_cipher_hex)

    print("\nFlag cipher (bytes):", flag_cipher)
    
    # Create a known plaintext that's the same length as the flag
    known_plain = b'A' * len(flag_cipher)
    print(f"\nSending plaintext of length {len(known_plain)}")
    
    # Send our known plaintext
    sock.send(known_plain)
    
    # Get response with encrypted version
    response = sock.recv(1024).decode('utf-8', errors='ignore')
    print("Server response for our input:", response)
    
    # Extract our ciphertext
    try:
        our_cipher_hex = response.split(': ')[1].strip()
        our_cipher = bytes.fromhex(our_cipher_hex)
    except Exception as e:
        print(f"Error processing server response: {e}")
        print("Full response:", response)
        return
    
    # Try both cat states
    our_cipher_alive = reverse_cat_box_alive(our_cipher)
    our_cipher_dead = reverse_cat_box_dead(our_cipher)
    
    # Since we know our plaintext was all 'A's, we can XOR to get potential keys
    potential_key_alive = xor_bytes(known_plain, our_cipher_alive)
    potential_key_dead = xor_bytes(known_plain, our_cipher_dead)
    
    # Try both potential keys to decrypt the flag
    flag_attempt_alive = xor_bytes(flag_cipher, potential_key_alive)
    flag_attempt_dead = xor_bytes(flag_cipher, potential_key_dead)
    
    print("\nPossible flag (if cat was alive):", flag_attempt_alive.decode('utf-8', errors='ignore'))
    print("Possible flag (if cat was dead):", flag_attempt_dead.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    solve_challenge()