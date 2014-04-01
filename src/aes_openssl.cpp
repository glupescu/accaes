#include "main.h"
//#include <openssl/aes.h>

AES_OPENSSL::AES_OPENSSL(uchar* buf_in, uchar* buf_out,
		uint buf_len, uchar* key, string aes_method) :
		AES_BASE(buf_in, buf_out, buf_len, key, aes_method){
}

void AES_OPENSSL::encrypt(){
/*
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);
	for(uint i=0; i<buf_len; i+=16)
		AES_ecb_encrypt((unsigned char*) buf_in+i,
				buf_out+i, &aes_key, AES_ENCRYPT);
				*/
}

void AES_OPENSSL::decrypt(){
/*
	AES_KEY aes_key;
	AES_set_decrypt_key(key, 128, &aes_key);
	for(uint i=0; i<buf_len; i+=16)
		AES_ecb_encrypt((unsigned char*) buf_in+i,
				buf_out+i, &aes_key, AES_DECRYPT);
				*/
}
