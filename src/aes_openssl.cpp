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
#include <openssl/aes.h>

/*******************************************************
*	Function: AES_OPENSSL
*******************************************************/
AES_OPENSSL::AES_OPENSSL(uchar* buf_in, uchar* buf_out,
		uint buf_len, uchar* key, uint key_len, string aes_method) :
		AES_BASE(buf_in, buf_out, buf_len, key, key_len, aes_method){
}

/*******************************************************
*	Function: encrypt
*******************************************************/
void AES_OPENSSL::encrypt(){
	AES_KEY aes_key;
	AES_set_encrypt_key(key, key_len* 8, &aes_key);
	for(uint i=0; i<buf_len; i+=16)
		AES_ecb_encrypt((unsigned char*) buf_in+i,
				buf_out+i, &aes_key, AES_ENCRYPT);
}

/*******************************************************
*	Function: decrypt
*******************************************************/
void AES_OPENSSL::decrypt(){
	AES_KEY aes_key;
	AES_set_decrypt_key(key, key_len* 8, &aes_key);
	for(uint i=0; i<buf_len; i+=16)
		AES_ecb_encrypt((unsigned char*) buf_in+i,
				buf_out+i, &aes_key, AES_DECRYPT);
}
