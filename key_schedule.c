#include <wmmintrin.h>
#include <emmintrin.h>
#include <stdint.h>
#if !defined (ALIGN16)
#if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct KEY_SCHEDULE
{
  ALIGN16 unsigned char KEY[16*15];
  unsigned int nr;
} AES_KEY;

static inline void key_expansion_128(__m128i* temp1,
			      __m128i* temp2,
			      int KS_Pointer,
			      __m128i *Key_Schedule)
{
  __m128i temp3;
  *temp2 = _mm_shuffle_epi32 (*temp2, 0xff);
  temp3 = _mm_slli_si128 (*temp1, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp3);
  *temp1 = _mm_xor_si128 (*temp1, *temp2);
  Key_Schedule[KS_Pointer]=*temp1;
}

void AES_128_Key_Expansion (const uint8_t *userkey,
			    AES_KEY *key)
{
  key->nr=10;
  __m128i temp1, temp2, temp3;
  __m128i *Key_Schedule=(__m128i*)key->KEY;
  int KS_Pointer=1;
  int i;
  temp1= _mm_loadu_si128((__m128i*)userkey);
  Key_Schedule[0]=temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x1);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
  temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
  key_expansion_128(&temp1, &temp2, KS_Pointer++, Key_Schedule);
}
