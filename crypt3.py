from Cryptodome.Util.number import bytes_to_long, long_to_bytes
from Cryptodome.Cipher import AES

def gf128_mul(x, y):
    R = 0xe1000000000000000000000000000000
    mask = (1 << 128) - 1
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        if x & 1:
            x = ((x >> 1) ^ R) & mask
        else:
            x = (x >> 1) & mask
        z &= mask
    return z

def gctr(key, icb, blocks):
    aes = AES.new(key, AES.MODE_ECB)
    out = b""
    counter = bytes_to_long(icb)
    for block in blocks:
        counter_bytes = long_to_bytes(counter, 16)
        encrypted = aes.encrypt(counter_bytes)
        out += xor_bytes(block, encrypted)
        counter += 1
        counter %= 2**128
    return out

def ghash(h, blocks):
    y = 0
    for block in blocks:
        y = gf128_mul(h, y ^ block)
    return y

# Inputs from NIST AES-GCM Encrypt Test 0
key = bytes.fromhex('77be63708971c4e240d1cb79e8d77feb')
aad = bytes.fromhex('7a43ec1d9c0a5a78a0b16533a6213cab')
iv = bytes.fromhex("e0e00f19fed7ba0136a797f3")
len_block = bytes.fromhex('00000000000000800000000000000000')  # AAD=128 bits, PT=0 bits

# Step 1: Compute H
aes = AES.new(key, AES.MODE_ECB)
H_bytes = aes.encrypt(bytes(16))  # All-zero block
H = bytes_to_long(H_bytes)

# Step 2: GHASH manual accumulation
AAD_int = bytes_to_long(aad)
LEN_int = bytes_to_long(len_block)

# Y₁ = (0 ⊕ AAD) · H
Y0 = 0
Y1 = gf128_mul(H, Y0 ^ AAD_int)

# Y₂ = (Y₁ ⊕ len_block) · H
#Y2 = gf128_mul(H, Y1 ^ LEN_int)
Y2 = ghash(H, [AAD_int, LEN_int])

import struct

aad_blocks = [bytes_to_long(aad[i:i+16]) for i in range(0, len(aad), 16)]
len_block = struct.pack(">QQ", len(aad)*8, 0)
LEN_int = bytes_to_long(len_block)

Y2 = ghash(H, aad_blocks + [LEN_int])

# Step 3: Compute J₀ (initial counter block)
# For 96-bit IVs: J₀ = IV || 0x00000001
J0 = iv + b'\x00\x00\x00\x01'
S_enc = aes.encrypt(J0)  # E_K(J₀)

# Step 4: Final Tag = E_K(J₀) ⊕ GHASH output
S_enc_int = bytes_to_long(S_enc)
tag_manual = S_enc_int ^ Y2
tag_manual_bytes = long_to_bytes(tag_manual, 16)

# AES-GCM reference
cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(b"")

# Output comparison
print("H           :", H_bytes.hex())
print("Y1          :", long_to_bytes(Y1, 16).hex())
print("Y2 (GHASH)  :", long_to_bytes(Y2, 16).hex())
print("E_K(J0)     :", S_enc.hex())
print("Tag (manual):", tag_manual_bytes.hex())
print("Tag (GCM)   :", tag.hex())
