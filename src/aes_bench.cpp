#include "main.h"

/*******************************************************
*	CLASS AES_BENCH - to be inherited
*******************************************************/

AES_BASE::AES_BASE(){ /* base does no initialization */ }

AES_BASE::AES_BASE(uchar* buf_in, uchar* buf_out, uint buf_len,
		uchar* key, string aes_method){

	/* init params */
	this->buf_in	= buf_in;
	this->buf_out	= buf_out;
	this->key		= key;
	this->buf_len	= buf_len;
	this->aes_method = aes_method;
}
