def gf128_mul(x: int, y: int) -> int:
    R = 0xE1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (y >> i) & 1:
            z ^= x
        if x & 1:
            x = (x >> 1) ^ R
        else:
            x >>= 1
    return z

x = 0x7CB681CD037B6D137A95F4DB99C48351
y = 0x7A43EC1D9C0A5A78A0B16533A6213CAB
product = gf128_mul(x, y)

print(x)
print(y)
print(hex(x))
print(hex(y))

# Convert each to 128-bit or 256-bit hex strings (padding if needed)
x_bytes = bytes.fromhex(f"{x:032x}")
y_bytes = bytes.fromhex(f"{y:032x}")
product_bytes = bytes.fromhex(f"{product:064x}")

# View byte arrays
print("x_bytes:", x_bytes.hex())
print("y_bytes:", y_bytes.hex())
print("product_bytes:", product_bytes.hex())
print(product)
print(hex(product))
