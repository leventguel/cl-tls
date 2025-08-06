#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
void gfmul (__m128i a, __m128i b, __m128i *res){
  __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6,
    tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
  __m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
  tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
  tmp4 = _mm_shuffle_epi32(a,78);
  tmp5 = _mm_shuffle_epi32(b,78);
  tmp4 = _mm_xor_si128(tmp4, a);
  tmp5 = _mm_xor_si128(tmp5, b);
  tmp4 = _mm_clmulepi64_si128(tmp4, tmp5, 0x00);
  tmp4 = _mm_xor_si128(tmp4, tmp3);
  tmp4 = _mm_xor_si128(tmp4, tmp6);
  tmp5 = _mm_slli_si128(tmp4, 8);
  tmp4 = _mm_srli_si128(tmp4, 8);
  tmp3 = _mm_xor_si128(tmp3, tmp5);
  tmp6 = _mm_xor_si128(tmp6, tmp4);
  tmp7 = _mm_srli_epi32(tmp6, 31);
  tmp8 = _mm_srli_epi32(tmp6, 30);
  tmp9 = _mm_srli_epi32(tmp6, 25);
  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);
  tmp8 = _mm_shuffle_epi32(tmp7, 147);
  tmp7 = _mm_and_si128(XMMMASK, tmp8);
  tmp8 = _mm_andnot_si128(XMMMASK, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp8);
  tmp6 = _mm_xor_si128(tmp6, tmp7);
  tmp10 = _mm_slli_epi32(tmp6, 1);
  tmp3 = _mm_xor_si128(tmp3, tmp10);
  tmp11 = _mm_slli_epi32(tmp6, 2);
  tmp3 = _mm_xor_si128(tmp3, tmp11);
  tmp12 = _mm_slli_epi32(tmp6, 7);
  tmp3 = _mm_xor_si128(tmp3, tmp12);
  *res = _mm_xor_si128(tmp3, tmp6);
}
