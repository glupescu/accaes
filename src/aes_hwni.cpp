#include "main.h"

#define KEYEXP(K, I) aes128_keyexpand(K, _mm_aeskeygenassist_si128(K, I))

__m128i aes128_keyexpand(__m128i key, __m128i keygened)
{
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));

	return _mm_xor_si128(key, keygened);
}


void key_expand(__m128i key, __m128i keyexp[])
{
	keyexp[0]  = _mm_load_si128((__m128i*)(&key));
	keyexp[1]  = KEYEXP(keyexp[0], 0x01);
        keyexp[2]  = KEYEXP(keyexp[1], 0x02);
        keyexp[3]  = KEYEXP(keyexp[2], 0x04);
        keyexp[4]  = KEYEXP(keyexp[3], 0x08);
        keyexp[5]  = KEYEXP(keyexp[4], 0x10);
        keyexp[6]  = KEYEXP(keyexp[5], 0x20);
        keyexp[7]  = KEYEXP(keyexp[6], 0x40);
        keyexp[8]  = KEYEXP(keyexp[7], 0x80);
        keyexp[9]  = KEYEXP(keyexp[8], 0x1B);
        keyexp[10] = KEYEXP(keyexp[9], 0x36);
}

void encrypt_hwni(uchar* buf_in, uchar* buf_out, __m128i key_exp_128i[])
{
	__m128i cipher_128i;
	_ALIGNED(16) unsigned char in_alligned[16];
	_ALIGNED(16) unsigned char out_alligned[16];

	// store plaintext in cipher variable than encrypt
	memcpy(in_alligned, buf_in, 16);
	cipher_128i = _mm_load_si128((__m128i *) in_alligned);

	cipher_128i = _mm_xor_si128(cipher_128i, key_exp_128i[0]);
	/* then do 9 rounds of aesenc, using the associated key parts */
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[1]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[2]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[3]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[4]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[5]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[6]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[7]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[8]);
        cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[9]);
	/* then 1 aesenclast rounds */
        cipher_128i = _mm_aesenclast_si128(cipher_128i, key_exp_128i[10]);

	// store back from register & copy to destination
	_mm_store_si128((__m128i *) out_alligned, cipher_128i);
	memcpy(buf_out, out_alligned, 16);
}

void decrypt_hwni(uchar* buf_in, uchar* buf_out, __m128i key_exp_128i[])
{
	__m128i cipher_128i;
	_ALIGNED(16) unsigned char in_alligned[16];
	_ALIGNED(16) unsigned char out_alligned[16];

	// store plaintext in cipher variable than encrypt
	memcpy(in_alligned, buf_in, 16);
	cipher_128i = _mm_load_si128((__m128i *) in_alligned);

	cipher_128i = _mm_xor_si128(cipher_128i, key_exp_128i[0]);
	/* then do 9 rounds of aesenc, using the associated key parts */
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[1]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[2]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[3]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[4]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[5]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[6]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[7]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[8]);
    cipher_128i = _mm_aesdec_si128(cipher_128i, key_exp_128i[9]);
	/* then 1 aesdeclast rounds */
    cipher_128i = _mm_aesdeclast_si128(cipher_128i, key_exp_128i[10]);

	// store back from register & copy to destination
	_mm_store_si128((__m128i *) out_alligned, cipher_128i);
	memcpy(buf_out, out_alligned, 16);
}

/*******************************************************
*	CLASS AES_HWNI
*******************************************************/

/* just store the values */
AES_HWNI::AES_HWNI(uchar* buf_in, uchar* buf_out, uint buf_len,
		uchar* key, string aes_method) :
		AES_BASE(buf_in, buf_out, buf_len, key, aes_method){
}

/*  do hardware assisted encryption - AES-NI */
#if 0
void AES_HWNI::encrypt()
{
	/* definitions */
	__m128i key_exp_128i[11], key_128i;
	uchar key_alligned[16] _ALIGNED(16);

	/* allign memory */
	memcpy(key_alligned, key, 16);
	key_128i = _mm_load_si128((__m128i *) key_alligned);

	/* expand the key */
	key_expand(key_128i, key_exp_128i);

	/* do encryption */
	for(uint i=0; i<len; i+=16)
		encrypt_hwni(&plain[i], &cipher[i], key_exp_128i);
}

#else
void AES_HWNI::encrypt()
{
	/* definitions */
	__m128i key_exp_128i[11], key_128i;
	_ALIGNED(16) uchar key_alligned[16];

	/* allign memory */
	memcpy(key_alligned, key, 16);
	key_128i = _mm_load_si128((__m128i *) key_alligned);

	/* expand the key */
	key_expand(key_128i, key_exp_128i);

	/* do encryption */
	uint i=0;
	uchar* buf_in_mp = &buf_in[0];
	uchar* buf_out_mp = &buf_out[0];
	uint buf_len_mp = buf_len;

	omp_set_num_threads(2);

	#pragma omp parallel for private(i) \
			firstprivate(buf_in_mp, buf_out_mp, key_exp_128i)
	for(i=0; i<buf_len_mp; i+=16)
		encrypt_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);

}
#endif

/* do hardware assisted decryption - AES-NI */
void AES_HWNI::decrypt()
{
	/* definitions */
	__m128i key_exp_128i[11], key_128i;
	_ALIGNED(16) uchar key_alligned[16];

	/* allign memory */
	memcpy(key_alligned, key, 16);
	key_128i = _mm_load_si128((__m128i *) key_alligned);

	/* expand the key */
	key_expand(key_128i, key_exp_128i);

	/* do encryption */
	for(uint i=0; i<buf_len; i+=16)
		decrypt_hwni(&buf_in[i], &buf_out[i], key_exp_128i);
}



