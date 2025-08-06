#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
extern void gfmul(__m128i a,__m128i b,__m128i* c); //must be implemented elsewhere
extern void reduce4 (__m128i H1,__m128i H2,__m128i H3,__m128i H4,
		     __m128i X1,__m128i X2,__m128i X3, __m128i X4, __m128i *res);
void AES_GCM_encrypt(const unsigned char *in,
		     unsigned char *out,
		     const unsigned char* addt,
		     const unsigned char* ivec,
		     unsigned char *tag,
		     int nbytes,
		     int abytes,
		     int ibytes,
		     const unsigned char* key,
		     int nr)
{
  int i, j ,k;
  __m128i hlp1, hlp2, hlp3, hlp4;
  __m128i tmp1, tmp2, tmp3, tmp4;
  __m128i H, H1, H2, H3, H4, Y, T;
  __m128i *KEY = (__m128i*)key;
  __m128i ctr1, ctr2, ctr3, ctr4;
  __m128i last_block = _mm_setzero_si128();
  __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
  __m128i FOUR = _mm_set_epi32(0, 4, 0, 0);
  __m128i BSWAP_EPI64 = _mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7);
  __m128i BSWAP_MASK = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
  __m128i X = _mm_setzero_si128();
  if(ibytes == 96/8){
    Y = _mm_loadu_si128((__m128i*)ivec);
    Y = _mm_insert_epi32(Y, 0x1000000, 3);
    /*(Compute E[ZERO, KS] and E[Y0, KS] together*/
    tmp1 = _mm_xor_si128(X, KEY[0]);
    tmp2 = _mm_xor_si128(Y, KEY[0]);
    for(j=1; j < nr-1; j+=2) {
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
      tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j+1]);
      tmp2 = _mm_aesenc_si128(tmp2, KEY[j+1]);
    };
    tmp1 = _mm_aesenc_si128(tmp1, KEY[nr-1]);
    tmp2 = _mm_aesenc_si128(tmp2, KEY[nr-1]);
    H = _mm_aesenclast_si128(tmp1, KEY[nr]);
    T = _mm_aesenclast_si128(tmp2, KEY[nr]);
    H = _mm_shuffle_epi8(H, BSWAP_MASK);
  }
  else{
    tmp1 = _mm_xor_si128(X, KEY[0]);
    for(j=1; j <nr; j++)
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
    H = _mm_aesenclast_si128(tmp1, KEY[nr]);
    H = _mm_shuffle_epi8(H, BSWAP_MASK);
    Y = _mm_xor_si128(Y, Y);
    for(i=0; i < ibytes/16; i++){
      tmp1 = _mm_loadu_si128(&((__m128i*)ivec)[i]);
      tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
      Y = _mm_xor_si128(Y, tmp1);
      gfmul(Y, H, &Y);
    }
    if(ibytes%16){
      for(j=0; j < ibytes%16; j++)
	((unsigned char*)&last_block)[j] = ivec[i*16+j];
      tmp1 = last_block;
      tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
      Y = _mm_xor_si128(Y, tmp1);
      gfmul(Y, H, &Y);
    }
    tmp1 = _mm_insert_epi64(tmp1, ibytes*8, 0);
    tmp1 = _mm_insert_epi64(tmp1, 0, 1);
    Y = _mm_xor_si128(Y, tmp1);
    gfmul(Y, H, &Y);
    Y = _mm_shuffle_epi8(Y, BSWAP_MASK);
    /*Compute E(K, Y0)*/
    tmp1 = _mm_xor_si128(Y, KEY[0]);
    for(j=1; j < nr; j++)
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
    T = _mm_aesenclast_si128(tmp1, KEY[nr]);
  }
  gfmul(H,H,&H2);
  gfmul(H,H2,&H3);
  gfmul(H,H3,&H4);
  for(i=0; i<abytes/16/4; i++){
    tmp1 = _mm_loadu_si128(&((__m128i*)addt)[i*4]);
    tmp2 = _mm_loadu_si128(&((__m128i*)addt)[i*4+1]);
    tmp3 = _mm_loadu_si128(&((__m128i*)addt)[i*4+2]);
    tmp4 = _mm_loadu_si128(&((__m128i*)addt)[i*4+3]);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
    tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
    tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);
    tmp1 = _mm_xor_si128(X, tmp1);
    reduce4(H, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &X);
  }
  for(i=i*4; i<abytes/16; i++){
    tmp1 = _mm_loadu_si128(&((__m128i*)addt)[i]);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    X = _mm_xor_si128(X,tmp1);
    gfmul(X, H, &X);
  }
  if(abytes%16){
    last_block = _mm_setzero_si128();
    for(j=0; j<abytes%16; j++)
      ((unsigned char*)&last_block)[j] = addt[i*16+j];
    tmp1 = last_block;
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    X =_mm_xor_si128(X,tmp1);
    gfmul(X,H,&X);
  }
  ctr1 = _mm_shuffle_epi8(Y, BSWAP_EPI64);
  ctr1 = _mm_add_epi32(ctr1, ONE);
  ctr2 = _mm_add_epi32(ctr1, ONE);
  ctr3 = _mm_add_epi32(ctr2, ONE);
  ctr4 = _mm_add_epi32(ctr3, ONE);
  for(i=0; i<nbytes/16/4; i++){
    tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
    tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
    tmp3 = _mm_shuffle_epi8(ctr3, BSWAP_EPI64);
    tmp4 = _mm_shuffle_epi8(ctr4, BSWAP_EPI64);
    ctr1 = _mm_add_epi32(ctr1, FOUR);
    ctr2 = _mm_add_epi32(ctr2, FOUR);
    ctr3 = _mm_add_epi32(ctr3, FOUR);
    ctr4 = _mm_add_epi32(ctr4, FOUR);
    tmp1 =_mm_xor_si128(tmp1, KEY[0]);
    tmp2 =_mm_xor_si128(tmp2, KEY[0]);
    tmp3 =_mm_xor_si128(tmp3, KEY[0]);
    tmp4 =_mm_xor_si128(tmp4, KEY[0]);
    for(j=1; j<nr-1; j+=2){
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
      tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);
      tmp3 = _mm_aesenc_si128(tmp3, KEY[j]);
      tmp4 = _mm_aesenc_si128(tmp4, KEY[j]);
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j+1]);
      tmp2 = _mm_aesenc_si128(tmp2, KEY[j+1]);
      tmp3 = _mm_aesenc_si128(tmp3, KEY[j+1]);
      tmp4 = _mm_aesenc_si128(tmp4, KEY[j+1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, KEY[nr-1]);
    tmp2 = _mm_aesenc_si128(tmp2, KEY[nr-1]);
    tmp3 = _mm_aesenc_si128(tmp3, KEY[nr-1]);
    tmp4 = _mm_aesenc_si128(tmp4, KEY[nr-1]);
    tmp1 =_mm_aesenclast_si128(tmp1, KEY[nr]);
    tmp2 =_mm_aesenclast_si128(tmp2, KEY[nr]);
    tmp3 =_mm_aesenclast_si128(tmp3, KEY[nr]);
    tmp4 =_mm_aesenclast_si128(tmp4, KEY[nr]);
    tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128(&((__m128i*)in)[i*4+0]));
    tmp2 = _mm_xor_si128(tmp2, _mm_loadu_si128(&((__m128i*)in)[i*4+1]));
    tmp3 = _mm_xor_si128(tmp3, _mm_loadu_si128(&((__m128i*)in)[i*4+2]));
    tmp4 = _mm_xor_si128(tmp4, _mm_loadu_si128(&((__m128i*)in)[i*4+3]));
    _mm_storeu_si128(&((__m128i*)out)[i*4+0], tmp1);
    _mm_storeu_si128(&((__m128i*)out)[i*4+1], tmp2);
    _mm_storeu_si128(&((__m128i*)out)[i*4+2], tmp3);
    _mm_storeu_si128(&((__m128i*)out)[i*4+3], tmp4);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
    tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
    tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);
    tmp1 = _mm_xor_si128(X, tmp1);
    reduce4(H, H2, H3, H4, tmp4, tmp3, tmp2, tmp1, &X);
  }
  for(k=i*4; k<nbytes/16; k++){
    tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
    ctr1 = _mm_add_epi32(ctr1, ONE);
    tmp1 = _mm_xor_si128(tmp1, KEY[0]);
    for(j=1; j<nr-1; j+=2){
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j+1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, KEY[nr-1]);
    tmp1 = _mm_aesenclast_si128(tmp1, KEY[nr]);
    tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128(&((__m128i*)in)[k]));
    _mm_storeu_si128(&((__m128i*)out)[k], tmp1);
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    X = _mm_xor_si128(X, tmp1);
    gfmul(X,H,&X);
  }
  //If remains one incomplete block
  if(nbytes%16){
    tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
    tmp1 = _mm_xor_si128(tmp1, KEY[0]);
    for(j=1; j<nr-1; j+=2){
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
      tmp1 = _mm_aesenc_si128(tmp1, KEY[j+1]);
    }
    tmp1 = _mm_aesenc_si128(tmp1, KEY[nr-1]);
    tmp1 = _mm_aesenclast_si128(tmp1, KEY[nr]);
    tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128(&((__m128i*)in)[k]));
    last_block = tmp1;
    for(j=0; j<nbytes%16; j++)
      out[k*16+j] = ((unsigned char*)&last_block)[j];
    for(j; j<16; j++)
      ((unsigned char*)&last_block)[j] = 0;
    tmp1 = last_block;
    tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
    X = _mm_xor_si128(X, tmp1);
    gfmul(X, H, &X);
  }
  tmp1 = _mm_insert_epi64(tmp1, nbytes*8, 0);
  tmp1 = _mm_insert_epi64(tmp1, abytes*8, 1);
  X = _mm_xor_si128(X, tmp1);
  gfmul(X,H,&X);
  X = _mm_shuffle_epi8(X, BSWAP_MASK);
  T = _mm_xor_si128(X, T);
  _mm_storeu_si128((__m128i*)tag, T);
}
