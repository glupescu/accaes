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

/*******************************************************
*	Function: verify
*	Info: verify ciphertext is correct against OpenSSL
*******************************************************/
void verify(uchar* buf_in,
		uchar* buf_out,
		uint buf_len,
		uchar* key,
		uint key_len)
{
	uchar* buf_out_ssl = new unsigned char[buf_len];
	DIE(buf_out_ssl == NULL, "Could not allocate memory buf_verify\n");

	AES_OPENSSL aes_validate(buf_in, buf_out_ssl, buf_len,
								key, key_len, "AES_OPENSSL");

	AES_PROFILER aes_profiler(buf_len);
	aes_profiler.start();
	aes_validate.encrypt();
	aes_profiler.stop("OpenSSL ");

	for(uint i=0; i<64; i++)
		printf("%02x ", buf_out[i]);
	cout << endl;

	for(uint i=0; i<64; i++)
		printf("%02x ", buf_out_ssl[i]);
	cout << endl;

	for(uint i=0; i<buf_len; i++)
		if(buf_out[i] != buf_out_ssl[i]){
			cout<< "DIFF first found " << i << endl;
				return;
		}
	cout << "PASS - matches OpenSSL encryption !!!" << endl;

	delete[] buf_out_ssl;
}

/*******************************************************
*	Function: main
*	Info: entry point
*******************************************************/
int main(int argc, char** argv)
{
	AES_OPTIONS aes_options;
	io_parse_options(argc, argv, aes_options);

	/* plainbuf_in */
	uint 	buf_len;
	uchar	*buf_in;
	uchar	*buf_out;

	uchar key[AES_KEY_LEN] = KEY_2;
	uint key_len = AES_KEY_LEN;
	aes_options.blk_op_mode = ECB;

	/* Read chunk, key */
	io_IN(buf_in, buf_out, aes_options);

	/* buf_len is file size */
	buf_len = aes_options.buf_len;

	/* base class object */
	AES_BASE* aes_work = NULL;
	AES_PROFILER aes_profiler(buf_len);

	/* ECB/CTR common processing */
	if(aes_options.processing_method == CPU_HWNI)
		aes_work = (AES_BASE*) new AES_HWNI(buf_in, buf_out, buf_len,
				key, key_len, "AES_HWNI", aes_options.cpu_count);
	else if(aes_options.processing_method == GPU)
		aes_work = (AES_BASE*) new AES_GPU(buf_in, buf_out, buf_len,
				key, key_len, "AES_GPU", aes_options.cl_device_ids[0]);
	else if(aes_options.processing_method == HYBRID)
		aes_work = (AES_BASE*) new AES_HYBRID(buf_in, buf_out, buf_len,
				key, key_len, "AES_HYBRID", aes_options);

	/* check valid memory allocation */
	DIE(aes_work==NULL, "Failed to allocate mem for aes_work object");

	/* perform encryption with profiling */
	aes_profiler.start();
	aes_work->encrypt();
	aes_profiler.stop("ACCAES ");

	/* write output file */
	verify(buf_in, buf_out, buf_len, key, key_len);
	io_OUT(buf_in, buf_out, aes_options);

}
