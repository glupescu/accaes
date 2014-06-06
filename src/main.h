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

/* Common headers C */
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <math.h>
#include <limits.h>
#include <vector>
#include <string>
#include <memory>
#include <unistd.h>

/* OpenMP support */
#include <omp.h>

/* SSE/AES headers */

#include <xmmintrin.h>
#include <wmmintrin.h>
#include <inttypes.h>


/* Common headers C++ */
#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>

/* OpenCL headers */
#include "CL/cl.h"

using namespace std;

#if defined(_MSC_VER)
#include <windows.h>
#define _ALIGNED(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define _ALIGNED(x) __attribute__ ((aligned(x)))
#endif
#endif

/* Force exit program on critical error */
#define DIE(assertion, call_description)		\
do {							\
	if (assertion) {				\
		fprintf(stderr, "(%s, %d): ",		\
		__FILE__, __LINE__);			\
		perror(call_description);		\
		exit(EXIT_FAILURE);			\
		}					\
		} while(0)

/*******************************
* Chunk sizes
********************************/

#define CHUNK_1MB (1024* 1024)
#define CHUNK_16MB (16* 1024* 1024)
#define CHUNK_32MB (32* 1024* 1024)
#define CHUNK_64MB (64* 1024* 1024)
#define CHUNK_128MB (128* 1024* 1024)
#define CHUNK_512MB (512* 1024* 1024)
#define CHUNK_1024MB (1024* 1024* 1024)

#define GPU_BUF_NUM			4
#define GPU_BUF_ALLOC_SIZE	(4* CHUNK_1MB)

/*******************************
* Datatypes
********************************/

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint
#define uint unsigned int
#endif


/*******************************
* Verfied {key, plain, cipher}
********************************/

/* key length */
#define AES128_KEY_LEN		16
#define AES256_KEY_LEN		32

/* chosen key length in algorithm */
#define AES_KEY_LEN			32

/* fixed key input */
#define KEY_1				{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,	\
							0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

#define KEY_2				{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,	\
							0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,	\
							0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,	\
							0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

/*******************************
* Internal stuff
********************************/

struct AES_OPTIONS;


/* I/O PGM files */
void io_parse_options(int argc, char** argv, AES_OPTIONS &aes_options);
void io_write_file(unsigned char *buffer, unsigned size, const char* filename);
void io_read_file(unsigned char* &buffer, unsigned &size, const char* filename);
void io_display_hex(unsigned char* buffer, unsigned size);
void io_display_ascii(unsigned char* buffer, unsigned size);

void io_IN(unsigned char * &buf_in, unsigned char * &buf_out,
		AES_OPTIONS& aes_opt);
void io_OUT(unsigned char * &buf_in, unsigned char * &buf_out,
		AES_OPTIONS aes_opt);

/* Test Procedure */
void pattern_memory_128(uchar* chunk, uint len, uchar* pattern);
bool pattern_check_128(uchar* chunk, uint len, uchar* pattern);

/*******************************
* External stuff
********************************/
void key128_expand(__m128i key[], __m128i keyexp[]);
void key256_expand(__m128i key[], __m128i keyexp[]);
void enc128_hwni(uchar* plain, uchar* cipher, __m128i key_exp_128i[]);
void enc256_hwni(uchar* plain, uchar* cipher, __m128i key_exp_128i[]);
void dec128_hwni(uchar* plain, uchar* cipher, __m128i key_exp_128i[]);
void dec256_hwni(uchar* plain, uchar* cipher, __m128i key_exp_128i[]);

/******************************************************
*	STRUCT OPTIONS
******************************************************/
enum BLOCK_OPERATION {ECB, CTR};
enum PROCESSOR_UNIT {CPU_HWNI, GPU, HYBRID};

struct AES_OPTIONS
{
	/* ecb or ccb */
	BLOCK_OPERATION blk_op_mode;

	/* encrypt or decrypt */
	bool encrypt;

	/* one time encrypt or loop demo */
	bool demo;

	/* benchmark mode */
	bool perf_mode;

	/* number iterations */
	int num_iterations;

	/* enc/dec processing method */
	int processing_method;

	/* in/out files */
	string file_in;
	string file_out;
	string key_in;
	string key_out;

	/* CL device ids */
	uint buf_len;
	int cpu_count;
	vector<uint> cl_device_ids;
	vector<uint> cl_device_splits;

};


/*******************************************************
*	CLASS AES_BASE - to be inherited
*******************************************************/

class AES_BASE
{
	public:
		string aes_method;
		uchar	*buf_in;
		uchar	*buf_out;
		uint 	buf_len;
		uchar	*key;
		uint	key_len;

		AES_BASE();
		AES_BASE(uchar* chunk_in, uchar* chunk_out, uint chunk_len,
				uchar* key, uint key_len, string aes_method);

		virtual void encrypt() = 0;
		virtual void decrypt() = 0;
};

/*******************************************************
*	CLASS AES_HWNI
*******************************************************/

class AES_HWNI : public AES_BASE
{
	public:
		/* for multicore configurations */
		int	cpu_count;

		/* just store the values */
		AES_HWNI(uchar* chunk_in, uchar* chunk_out, uint chunk_len,
				uchar* key, uint key_len, string aes_method, int cpu_count);

		/*  do hardware assisted encryption - AES-NI */
		void encrypt();

		/* do hardware assisted decryption - AES-NI */
		void decrypt();
};


/*******************************************************
*	CLASS AES_GPU
*******************************************************/

#define NUM_DEVICES 2
#define NUM_BUFFERS 2
#define NUM_KERNELS 1

#define MAX_PLATFORMS 2
#define DEFAULT_PLATFORM_CL 0
#define MAX_STR_SIZE 512
#define MAX_DEVICE_COUNT 4

struct CL_ComputeDevice
{
	/* CL code */
	cl_program		dev_program;
	cl_kernel		dev_kernel_enc128;
	cl_kernel		dev_kernel_dec128;
	cl_kernel		dev_kernel_enc256;
	cl_kernel		dev_kernel_dec256;
	cl_kernel		dev_kernel_sel;
	cl_context		dev_context;
	cl_command_queue dev_cmd_queue;
	cl_command_queue dev_cmd_queue_io;
	cl_command_queue dev_cmd_queue_iow;
	cl_device_id	dev_id;
	cl_platform_id	dev_platform;

	/* CL buffers */
	cl_mem	buffer_in;
	cl_mem	buffer_out;
	cl_mem	buffer_keys;

	/* CL info */
	string info_name;
	cl_int info_type;
};

class AES_GPU : public AES_BASE
{
	cl_device_id cl_devices[NUM_DEVICES];
	cl_platform_id cl_platforms[MAX_PLATFORMS];

	cl_uint cl_num_devices;
	CL_ComputeDevice dev_gpu;

	public:
		/* constructor, just store the values */
		AES_GPU(uchar* chunk_in, uchar* chunk_out, uint chunk_len,
				uchar* key, uint key_len, string aes_method,
				cl_uint usr_device_id);

		/* constructor, clear CL env */
		~AES_GPU();

		/* init gpu */
		void init_gpu(cl_uint usr_device_id);

		/*  do hardware assisted encryption - AES-NI */
		void encrypt();
		void encrypt_overlap();
		void encrypt_no_overlap();

		/* do hardware assisted decryption - AES-NI */
		void decrypt();
};

/*******************************************************
*	CLASS AES_HYBRID
*******************************************************/

#define AES_MAX_GPU_NUM 5

class AES_HYBRID : public AES_BASE
{
	public:
		AES_HWNI*		aes_hwni;
		AES_GPU*		aes_gpus[AES_MAX_GPU_NUM];
		vector<uint> cl_user_ids;
		vector<uint> cl_user_splits;

		/* for multicore configurations */
		float		gpu_work_fraction;

		/* just store the values */
		AES_HYBRID(uchar* chunk_in, uchar* chunk_out, uint chunk_len,
				uchar* key, uint key_len, string aes_method, AES_OPTIONS aes_options);

		/*  do encryption - hw acc */
		void encrypt();

		/* do decryption - hw acc */
		void decrypt();
};

/*******************************************************
*	CLASS AES_OPENSSL for perf comparison
*******************************************************/

class AES_OPENSSL : public AES_BASE
{
	public:
		/* just store the values */
		AES_OPENSSL(uchar* chunk_in, uchar* chunk_out, uint chunk_len,
				uchar* key, uint key_len, string aes_method);

		/*  do encryption - hw acc */
		void encrypt();

		/* do decryption - hw acc */
		void decrypt();
};


/*******************************************************
*	CLASS AES_PROFILER
*******************************************************/

class AES_PROFILER
{
	private:

#if defined(_MSC_VER)
		__int64 starttime;
		__int64 endtime;
#else
#if defined(__GNUC__)
		struct timespec starttime;
		struct timespec endtime;
#endif
#endif

		long double time_diff;
		long double throughput;
		long buf_len;

	public:
		AES_PROFILER(long buf_len);
		void start();
		void stop(const char* msg);
};
