/*
 * 	Copyright (C) 2013-2014  Lupescu Grigore, grigore.lupescu@gmail.com
 * 	ACCAES - AES encryption on commodity hardware (CPU AESNI, GPGPU)
 *
 *	This file is part of ACCAES.
 *
 *	ACCAES is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	ACCAES is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with ACCAES.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "main.h"

/* _mm_aeskeygenassist_si128(K2, R), K2 - key && R - round */
#define KEY_EXP_FF(K1, K2, R) key_expand_FF(K1, _mm_aeskeygenassist_si128(K2, R))
#define KEY_EXP_AA(K1, K2, R) key_expand_AA(K1, _mm_aeskeygenassist_si128(K2, R))

/*******************************************************
*	Function: key_expand_FF
*******************************************************/
__m128i key_expand_FF(__m128i key, __m128i keygened)
{
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	keygened = _mm_shuffle_epi32(keygened, 0xFF);

	return _mm_xor_si128(key, keygened);
}

/*******************************************************
*	Function: key_expand_AA
*******************************************************/
__m128i key_expand_AA(__m128i key, __m128i keygened)
{
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	keygened = _mm_shuffle_epi32(keygened, 0xAA);

	return _mm_xor_si128(key, keygened);
}

/*******************************************************
*	Function: key128_expand
*******************************************************/
void key128_expand(__m128i key[], __m128i keyexp[])
{
	keyexp[0]  = _mm_load_si128(&key[0]);
	keyexp[1]  = KEY_EXP_FF(keyexp[0], keyexp[0], 0x01);
    keyexp[2]  = KEY_EXP_FF(keyexp[1], keyexp[1], 0x02);
    keyexp[3]  = KEY_EXP_FF(keyexp[2], keyexp[2], 0x04);
    keyexp[4]  = KEY_EXP_FF(keyexp[3], keyexp[3], 0x08);
    keyexp[5]  = KEY_EXP_FF(keyexp[4], keyexp[4], 0x10);
    keyexp[6]  = KEY_EXP_FF(keyexp[5], keyexp[5], 0x20);
    keyexp[7]  = KEY_EXP_FF(keyexp[6], keyexp[6], 0x40);
    keyexp[8]  = KEY_EXP_FF(keyexp[7], keyexp[7], 0x80);
    keyexp[9]  = KEY_EXP_FF(keyexp[8], keyexp[8], 0x1B);
    keyexp[10] = KEY_EXP_FF(keyexp[9], keyexp[9], 0x36);
}

/*******************************************************
*	Function: key256_expand
*******************************************************/
void key256_expand(__m128i key[], __m128i keyexp[])
{
	keyexp[0]  = _mm_load_si128(&key[0]);
	keyexp[1]  = _mm_load_si128(&key[1]); //_mm_loadu_si128((const __m128i*) (key+16));
	keyexp[2]  = KEY_EXP_FF(keyexp[0], keyexp[1], 0x01);
    keyexp[3]  = KEY_EXP_AA(keyexp[1], keyexp[2], 0x00);
	keyexp[4]  = KEY_EXP_FF(keyexp[2], keyexp[3], 0x02);
    keyexp[5]  = KEY_EXP_AA(keyexp[3], keyexp[4], 0x00);
	keyexp[6]  = KEY_EXP_FF(keyexp[4], keyexp[5], 0x04);
    keyexp[7]  = KEY_EXP_AA(keyexp[5], keyexp[6], 0x00);
	keyexp[8]  = KEY_EXP_FF(keyexp[6], keyexp[7], 0x08);
    keyexp[9]  = KEY_EXP_AA(keyexp[7], keyexp[8], 0x00);
	keyexp[10]  = KEY_EXP_FF(keyexp[8], keyexp[9], 0x10);
    keyexp[11]  = KEY_EXP_AA(keyexp[9], keyexp[10], 0x00);
	keyexp[12]  = KEY_EXP_FF(keyexp[10], keyexp[11], 0x20);
    keyexp[13]  = KEY_EXP_AA(keyexp[11], keyexp[12], 0x00);
    keyexp[14]  = KEY_EXP_FF(keyexp[12], keyexp[13], 0x40);
}

/*******************************************************
*	Function: enc128_hwni
*******************************************************/
void enc128_hwni(uchar* buf_in, uchar* buf_out, __m128i key_exp_128i[])
{
	__m128i cipher_128i;
	_ALIGNED(16) unsigned char in_alligned[16];
	_ALIGNED(16) unsigned char out_alligned[16];

	/* load into register */
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

/*******************************************************
*	Function: enc256_hwni
*******************************************************/
void enc256_hwni (uchar* buf_in, uchar* buf_out, __m128i key_exp_128i[])
{
	__m128i cipher_128i;
	unsigned char in_alligned[16] _ALIGNED(16);
	unsigned char out_alligned[16] _ALIGNED(16);

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
    cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[10]);
    cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[11]);
    cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[12]);
    cipher_128i = _mm_aesenc_si128(cipher_128i, key_exp_128i[13]);

	/* then 1 aesdeclast rounds */
    cipher_128i = _mm_aesenclast_si128(cipher_128i, key_exp_128i[14]);

	// store back from register & copy to destination
	_mm_store_si128((__m128i *) out_alligned, cipher_128i);
	memcpy(buf_out, out_alligned, 16);
}

/*******************************************************
*	CLASS AES_HWNI
*******************************************************/

/* just store the values */
AES_HWNI::AES_HWNI(uchar* buf_in, uchar* buf_out, uint buf_len,
		uchar* key, uint key_len, string aes_method, int cpu_count) :
		AES_BASE(buf_in, buf_out, buf_len, key, key_len, aes_method){
		this->cpu_count = cpu_count;
}

/*******************************************************
*	Function: encrypt
*	Info: do hardware assisted encryption - AES-NI
*******************************************************/
void AES_HWNI::encrypt()
{
	uint i=0;
	uchar* buf_in_mp = &buf_in[0];
	uchar* buf_out_mp = &buf_out[0];
	uint buf_len_mp = buf_len;

	/* definitions */
	__m128i key_exp_128i[15], key_128i[2];

	/* allign memory */
	if(key_len == 16){
		_ALIGNED(16) uchar key_alligned[16];
		memcpy(key_alligned, key, 16);
		key_128i[0] = _mm_load_si128((__m128i *) key_alligned);

		/* expand 128 bit key */
		key128_expand(key_128i, key_exp_128i);

		/* for number of threads according to user CLI */
		omp_set_num_threads(cpu_count);

		/* do encryption */
		#pragma omp parallel for private(i) schedule(dynamic, 4096) \
				firstprivate(buf_in_mp, buf_out_mp, key_exp_128i)
		for(i=0; i<buf_len_mp; i+=16){
			enc128_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);
		}
	}
	else if(key_len == 32){

		_ALIGNED(32) uchar key_alligned[32];
		memcpy(key_alligned, key, 32);
		key_128i[0] = _mm_load_si128((__m128i *) key_alligned);
		key_128i[1] = _mm_load_si128((__m128i *) key_alligned + 1);

		/* expand 256 bit key */
		key256_expand(key_128i, key_exp_128i);

		/* for number of threads according to user CLI */
		omp_set_num_threads(cpu_count);

		/* do encryption */
		#pragma omp parallel for private(i) \
				firstprivate(buf_in_mp, buf_out_mp, key_exp_128i)
		for(i=0; i<buf_len_mp; i+=16)
			enc256_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);
	}
}

/*******************************************************
*	Function: decrypt
*******************************************************/
void AES_HWNI::decrypt()
{
	/* not implemented */
}



