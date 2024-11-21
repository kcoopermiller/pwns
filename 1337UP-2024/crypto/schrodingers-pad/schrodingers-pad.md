# Crypto: Schrodinger's Pad

This is a fairly simple puzzle that involves reversing a faulty one-time pad encryption

Let's walk thru the `server.py` code to understand the problem more:

**One-time Pad**
OTP is a type of encryption where each byte of the plaintext is XORed with a corresponding byte from a random key.

```python
# XOR Truth Table (^ == XOR)
0 ^ 0 = 0
0 ^ 1 = 1
1 ^ 0 = 1
1 ^ 1 = 0

a ^ a = 0        # XOR with self gives 0
a ^ 0 = a        # XOR with 0 gives original value
(a ^ b) ^ b = a  # XOR is reversible with same value (important!)
```

```python
def otp(p, k):
    # If plaintext is longer than key, repeat the key
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    # XOR each byte of plaintext with corresponding byte of key
    return bytes([p ^ k for p, k in zip(p, k_r)])
```


**Cat Box 🐱**
This is an additional transformation applied after OTP

```python
def check_cat_box(ciphertext, cat_state):
    # cat_state can be 0 (dead) or 1 (alive)
    c = bytearray(ciphertext)
    if cat_state == 1:
        # Alive state: left shift and XOR with 0xAC
        for i in range(len(c)):
            c[i] = ((c[i] << 1) & 0xFF) ^ 0xAC
    else:
        # Dead state: rotate right and XOR with 0xCA
        for i in range(len(c)):
            c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
            c[i] ^= 0xCA
    return bytes(c)
```

The 0xFF in binary is 11111111. So, when we do & 0xFF, we're essentially keeping only the last 8 bits (1 byte) of a number
```python
bin(149) # 10010101
bin(149 << 1) # 100101010
bin((149 << 1) & 0xff) # 00101010
```

The important part is that both transformations are reversible:
For Alive state: 
1. XOR with 0xAC
2. Right shift (and set first bit based on overflow)

For Dead state:
1. XOR with 0xCA
2. Left rotate by 1

**Server**
The server uses these algorithms in the following way:
1. Shows us the flag encrypted with ONLY OTP (no cat box)
2. Encrypts our input with OTP using **the same key**
3. Then applies the cat box transformation

## The Vulnerability

The vulnerability lies in the server's choice are reusing the same key to encrypt both flag and our input:

```python
flag_cipher = flag ^ key              # Server encrypts flag
our_cipher = cat_box(our_input ^ key) # Server encrypts our input

# We can recover the key because:
reversed_cipher = reverse_cat_box(our_cipher)  # Now we have: our_input ^ key
key = reversed_cipher ^ our_input              # XORing with our known input gives key
# This works because:
reversed_cipher ^ our_input 
    = (our_input ^ key) ^ our_input 
    = our_input ^ key ^ our_input 
    = key                                      # our_input cancels out, leaving just key
```

So, this vulnerability allow us to:
1. Send known plaintext
2. Get it back encrypted with both OTP and cat box
3. Reverse the cat box
4. XOR reversed cipher with our input to get key
5. Use key to decrypt flag (which only used OTP)

# Solution

First we need to reverse the dead or alive algorithms:
```python
def reverse_cat_box_alive(ciphertext):
    # Reverses the cat_state=1 transformation
    c = bytearray(ciphertext)
    for i in range(len(c)):
        c[i] ^= 0xAC  # First undo the XOR
        c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF  # Then right shift to undo left shift
    return bytes(c)

def reverse_cat_box_dead(ciphertext):
    # Reverses the cat_state=0 transformation
    c = bytearray(ciphertext)
    for i in range(len(c)):
        c[i] ^= 0xCA  # First undo the XOR
        c[i] = ((c[i] << 1) | (c[i] >> 7)) & 0xFF  # Then left shift to undo right shift/rotate
    return bytes(c)
```

Then we can begin reversing the encryption in the order mentioned above

```python
# Try both cat states
our_cipher_alive = reverse_cat_box_alive(our_cipher)
our_cipher_dead = reverse_cat_box_dead(our_cipher)

# Since we know our plaintext, we can XOR to get potential keys
potential_key_alive = xor_bytes(known_plain, our_cipher_alive)
potential_key_dead = xor_bytes(known_plain, our_cipher_dead)

# Try both potential keys to decrypt the flag
flag_attempt_alive = xor_bytes(flag_cipher, potential_key_alive)
flag_attempt_dead = xor_bytes(flag_cipher, potential_key_dead)

# One of these will contain flag
print("\nPossible flag (if cat was alive):", flag_attempt_alive.decode('utf-8', errors='ignore'))
print("Possible flag (if cat was dead):", flag_attempt_dead.decode('utf-8', errors='ignore'))
```
