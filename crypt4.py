from Cryptodome.Cipher import AES
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import struct

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

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

def ghash(H, blocks):
    y = 0
    for block in blocks:
        y = gf128_mul(H, y ^ block)
    return y

def gf128_mul(x, y):
    R = 0xe1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        msb = x & (1 << 127)
        x = (x << 1) & ((1 << 128) - 1)
        if msb:
            x ^= R
    return z & ((1 << 128) - 1)

# -- Inputs --
key = bytes.fromhex("77be63708971c4e240d1cb79e8d77feb")
iv = bytes.fromhex("e0e00f19fed7ba0136a797f3")
aad = bytes.fromhex("7a43ec1d9c0a5a78a0b16533a6213cab")
pt = b""

# -- Step 1: Compute H = AES_K(0^128) --
aes_ecb = AES.new(key, AES.MODE_ECB)
H = bytes_to_long(aes_ecb.encrypt(bytes(16)))

# -- Step 2: Split inputs into blocks --
def split_blocks(data):
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    if len(blocks) == 0 or len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16, b"\x00")
    return blocks

aad_blocks = split_blocks(aad)
pt_blocks = split_blocks(pt) if pt else []

aad_ints = [bytes_to_long(b) for b in aad_blocks]
pt_ints = [bytes_to_long(b) for b in pt_blocks]

len_block = struct.pack(">QQ", len(aad)*8, len(pt)*8)
len_int = bytes_to_long(len_block)

# -- Step 3: GHASH of (AAD || PT || len) --
S = ghash(H, aad_ints + pt_ints + [len_int])

# -- Step 4: Compute J₀ (96-bit IV case) --
J0 = iv + b'\x00\x00\x00\x01'

# -- Step 5: Tag = AES_K(J₀) ⊕ S --
S_enc = aes_ecb.encrypt(J0)
tag = xor_bytes(S_enc, long_to_bytes(S, 16))

print("Manual Tag:", tag.hex())
