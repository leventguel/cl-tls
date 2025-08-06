function gf128Mul(x, y) {
  const R = BigInt("0xE1000000000000000000000000000000");
  let z = 0n;

  for (let i = 0; i < 128; i++) {
    if ((y >> BigInt(i)) & 1n) {
      z ^= x;
    }
    if (x & 1n) {
      x = (x >> 1n) ^ R;
    } else {
      x >>= 1n;
    }
  }
  return z;
}

x = int("7CB681CD037B6D137A95F4DB99C48351", 16);
y = int("7A43EC1D9C0A5A78A0B16533A6213CAB", 16);
console.log(hex(gf128_mul(x, y)));
