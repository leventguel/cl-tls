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
Y1 = gf128_mul(H, AAD_int)

# Y₂ = (Y₁ ⊕ len_block) · H
Y2 = gf128_mul(H, Y1 ^ LEN_int)

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(b"")

print("H      :", H_bytes.hex())
print("Y1     :", long_to_bytes(Y1, 16).hex())
print("Y2     :", long_to_bytes(Y2, 16).hex())
print("Tag:", tag.hex())
