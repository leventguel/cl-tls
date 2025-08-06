#include <stdint.h>
#include <stdio.h>

void print_uint128(__uint128_t n) {
    uint64_t high = n >> 64;
    uint64_t low  = (uint64_t)n;
    printf("%016llX%016llX\n", (unsigned long long)high, (unsigned long long)low);
}

__uint128_t gf128mul(__uint128_t x, __uint128_t y) {
    __uint128_t R = (__uint128_t)0xe100000000000000ULL << 64;
    __uint128_t z = 0;


    for (int i = 0; i < 128; i++) {
      if (y & ((__uint128_t)1 << (127 - i))) {
            z ^= x;
        }
	printf("Round %3d: x = ", i); print_uint128(x);
        x = (x << 1) ^ ((x >> 127) ? R : 0);
    }

    /*
    for (int i = 0; i < 128; i++) {
    if (y & ((__uint128_t)1 << i)) {
        z ^= x;
    }
    printf("Round %3d: x = ", i); print_uint128(x);
    x = (x << 1) ^ ((x >> 127) ? R : 0);
    }
    */
    return z;
}

int main() {
    __uint128_t H = ((__uint128_t)0xFFFFFFFFFFFFFFFFULL << 64) | 0xFFFFFFFFFFFFFFFFULL;
    __uint128_t block = H;

    __uint128_t result = gf128mul(H, block);
    printf("Result = ");
    print_uint128(result);
    return 0;
}
