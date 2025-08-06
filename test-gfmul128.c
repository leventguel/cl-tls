#include <stdint.h>
#include <stdio.h>
#include <string.h>

// GHASH reduction polynomial: x^128 + x^7 + x^2 + x + 1
static const uint8_t R[16] = {
    0xe1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void gf128_mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    uint8_t tmp[16];
    memset(z, 0, 16);
    memcpy(v, x, 16);

    for (int i = 0; i < 128; i++) {
        int byte = i / 8;
        int bit = 7 - (i % 8); // MSB-first

        if ((y[byte] >> bit) & 1) {
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        }

        // Shift v left by 1 bit
        uint8_t carry = v[0] >> 7;
        for (int j = 0; j < 15; j++)
            v[j] = (v[j] << 1) | (v[j+1] >> 7);
        v[15] <<= 1;

        // Apply reduction if carry is set
        if (carry) {
            for (int j = 0; j < 16; j++)
                v[j] ^= R[j];
        }
    }
}

int main() {
    uint8_t x[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t y[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t z[16];

    gf128_mul(z, x, y);

    printf("Result = ");
    for (int i = 0; i < 16; i++)
        printf("%02X", z[i]);
    printf("\n");

    // Expected: D3E039B9DC59C2550B6636B9E0EBBA58
}
