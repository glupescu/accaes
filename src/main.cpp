#include "main.h"

void pattern_memory_128(uchar* chunk, uint len, uchar* pattern)
{
	DIE(chunk == NULL, "Memory not valid\n");
	for(uint i=0; i<len; i+=16)
		memcpy(&chunk[i], pattern, 16);
}

bool pattern_check_128(uchar* chunk, uint len, uchar* pattern)
{
	DIE(chunk == NULL, "Memory not valid\n");
	for(uint i=0; i<len; i+=16)
		if(memcmp(&chunk[i], pattern, 16) !=0)
			return false;

	return true;
}

int main(int argc, char** argv)
{
	AES_OPTIONS aes_options;
	io_parse_options(argc, argv, aes_options);

	/* plainbuf_in */
	uint 	buf_len = aes_options.buf_len;
	uchar	*buf_in;
	uchar	*buf_out;
	uchar key[16] = KEY_1;

	/* Read chunk, key */
	io_IN(buf_in, buf_out, aes_options);

	/* base class object */
	AES_BASE* aes_work = NULL;
	AES_PROFILER aes_profiler(buf_len);

	/* select processing method */
	if(aes_options.processing_method == CPU_HWNI)
		aes_work = (AES_BASE*) new AES_HWNI(buf_in, buf_out, buf_len,
				key, "AES_HWNI");
	else if(aes_options.processing_method == GPU){
		aes_work = (AES_BASE*) new AES_GPU(buf_in, buf_out, buf_len,
				key, "AES_GPU", aes_options.cl_device_ids[0]);
	}
	else if(aes_options.processing_method == HYBRID)
		aes_work = (AES_BASE*) new AES_HYBRID(buf_in, buf_out, buf_len,
				key, "AES_HYBRID", aes_options);

	/* check valid memory allocation */
	DIE(aes_work==NULL, "Failed to allocate mem for aes_work object");

	/* start timer */
	aes_profiler.start();

	/* perform operation */
	if(aes_options.enc_dec == ENCRYPT)
		aes_work->encrypt();
	else
		aes_work->decrypt();

	/* stop timer */
	cout << "PERFORMANCE ";
	aes_profiler.stop();

	/* write output file */
	io_OUT(buf_in, buf_out, aes_options);
}
