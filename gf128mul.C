#include <stdio.h>

void print(__uint128_t value) {

  long long hi = value >> 64;
  long long lo = value & 0xffffffffffffffffll;

  fprintf(stdout, "%016llx%016llx\n", hi, lo);

}

__uint128_t multiply(__uint128_t X, __uint128_t Y) {

  __uint128_t R = ((__uint128_t)0xe1) << 120;
  __uint128_t Z = 0;
  __uint128_t V = X;

  for (unsigned char i=0; i < 128; i++) {

    __uint128_t mask = ((__uint128_t)1) << (127 - i);

    if( (Y & mask) != 0) {

      Z = Z ^ V;

    }

    if( (V & 1) == 0) {

      V >>= 1;

    }

    else {

      V = (V >> 1) ^ R;

    }

  }

  return Z;

}

int main (int argc, char *argv[]) {

  __uint128_t R = ((__uint128_t)0x952b2a56a5604ac0 << 64) | 0xb32b6656a05b40b6;
  __uint128_t S = ((__uint128_t)0xdfa6bf4ded81db03 << 64) | 0xffcaff95f830f061;

  print(multiply(R,S));

  __uint128_t RR = 1;
  __uint128_t SS = 1;

  print(multiply(RR,SS));
}
