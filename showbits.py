def show_bits(value, width=128):
    print("Bit Index (MSB ➞ LSB):")
    for i in range(width - 1, -1, -1):
        bit = (value >> i) & 1
        print(bit, end='')
        if i % 8 == 0:
            print(' ', end='')
    print("\n")

# 🔍 Example usage
number = 0x80000000000000000000000000000001  # MSB and LSB are 1
show_bits(number)
