#include <stdint.h>
#include <stdio.h>
#include <string.h>

// GHASH reduction: x^128 + x^7 + x^2 + x + 1 -> 0xe1 in MSB
void gf128_mul(uint8_t result[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    memset(result, 0, 16);
    memcpy(v, x, 16);

    for (int i = 0; i < 128; i++) {
        int byte = i / 8;
        int bit = 7 - (i % 8);

        // Conditional XOR
        if ((y[byte] >> bit) & 1) {
            for (int j = 0; j < 16; j++)
                result[j] ^= v[j];
        }

        // Shift v left by one bit (carry-aware)
        uint8_t carry = 0;
        for (int j = 15; j >= 0; j--) {
            uint8_t next = v[j] >> 7;
            v[j] = (v[j] << 1) | carry;
            carry = next;
        }

        // Apply GHASH reduction polynomial if carry out
        if (carry)
            v[0] ^= 0xe1;
    }
}

int main() {
    uint8_t x[16] = { [0 ... 15] = 0xFF };
    uint8_t y[16] = { [0 ... 15] = 0xFF };
    uint8_t z[16];

    gf128_mul(z, x, y);

    printf("Result = ");
    for (int i = 0; i < 16; i++)
        printf("%02X", z[i]);
    printf("\n");

    // Expected: D3E039B9DC59C2550B6636B9E0EBBA58
    return 0;
}
