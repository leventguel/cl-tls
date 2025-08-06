def gf128_reduce(x):
    """Reduce 256-bit polynomial modulo x^128 + x^7 + x^2 + x + 1"""
    modulus = 0x87  # x^7 + x^2 + x + 1 in hex
    for i in range(255, 127, -1):  # Reduce overflow bits
        if (x >> i) & 1:
            x ^= modulus << (i - 128)
    return x & ((1 << 128) - 1)

def gf128_mul(a, b):
    """Carryless GF(2^128) multiplication"""
    result = 0
    for i in range(128):
        if (b >> i) & 1:
            result ^= a << i
    return gf128_reduce(result)

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

def format_hex128(val):
    return f'{val:032X}'

# Generate table for inputs 1, 2, 4, ..., 128
inputs = [1 << i for i in range(8)]  # LSB to bit 7
print(" GF(2^128) Multiplication Table")
print(" ┌────────────┬────────────┐")
print(" │   x * x    │   Result   │")
print(" ├────────────┼────────────┤")
for x in inputs:
    res = gf128_mul(x, x)
    print(f" │ {format_hex128(x)} │ {format_hex128(res)} │")
print(" └────────────┴────────────┘")
