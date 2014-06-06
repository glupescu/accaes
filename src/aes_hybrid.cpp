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

/*	plain_gpu		plain_cpu
 * 		\/			\/
 * 		*-------------------------------*
 * 		*	WORK	|		WORK		*
 * 		*	GPU		|		CPU			*
 * 		*	AES		|		AES			*
 * 		*-------------------------------*
 */

/*******************************************************
*	Function: AES_HYBRID
*	Info: static work split amongst CPU and GPGPU
*******************************************************/
AES_HYBRID::AES_HYBRID(uchar* buf_in,
		uchar* buf_out,
		uint buf_len,
		uchar* key,
		uint key_len,
		string aes_method,
		AES_OPTIONS aes_options) :

		AES_BASE(buf_in,
				buf_out,
				buf_len,
				key,
				key_len,
				aes_method){

		/* Space for GPU to work on */
		uchar* buf_in_gpu	= 	NULL;
		uchar* buf_out_gpu	=	NULL;
		uint buf_len_gpu	=	0;
		uchar* buf_in_hwni	=	NULL;
		uchar* buf_out_hwni	=	NULL;
		uint buf_len_hwni	=	buf_len;

		cl_user_ids = aes_options.cl_device_ids;
		cl_user_splits = aes_options.cl_device_splits;

		DIE(cl_user_ids.size() != cl_user_splits.size(),
				"Num CL devices and num splits are inequal, error from CLI");

		/* offsets are 0 */
		buf_in_gpu	=	buf_in;
		buf_out_gpu	=	buf_out;
		buf_len_gpu =	0;

		for(uint i=0; i<cl_user_ids.size(); i++)
		{
			/* computing space for GPU to work on */
			buf_in_gpu	+= buf_len_gpu;
			buf_out_gpu	+= buf_len_gpu;
			buf_len_gpu = buf_len * ((double)cl_user_splits[i] / (double)100);
			buf_len_gpu -= (buf_len_gpu % (GPU_BUF_ALLOC_SIZE));

			/* CPU has less work */
			buf_len_hwni -= buf_len_gpu;

			/* init and push GPU */
			aes_gpus[i] = new AES_GPU(buf_in_gpu, buf_out_gpu, buf_len_gpu,
					key, key_len, aes_method, cl_user_ids[i]);
		}

		/* computing space for CPU left space to work on */
		buf_in_hwni		=	buf_in_gpu + buf_len_gpu;
		buf_out_hwni	=	buf_out_gpu + buf_len_gpu;

		/* init CPU */
		aes_hwni = new AES_HWNI(buf_in_hwni, buf_out_hwni, buf_len_hwni,
						key, key_len, aes_method, aes_options.cpu_count);
	}

/*******************************************************
*	Function: encrypt
*	Info: encrypt cpu+gpu
*******************************************************/
void AES_HYBRID::encrypt(){

	/* for number of threads according to user CLI */
	int cpu_count = aes_hwni->cpu_count;
	omp_set_num_threads(cpu_count + cl_user_ids.size());

	#pragma omp parallel firstprivate(cpu_count)
	{
		if(omp_get_thread_num() >= cpu_count){
			uint tid = omp_get_thread_num();
			AES_PROFILER aes_profiler( \
					aes_gpus[tid - cpu_count]->buf_len);

			/* start timer */
			aes_profiler.start();

			/* do encryption & time it */
			aes_gpus[tid - cpu_count]->encrypt();

			/* stop timer */
			aes_profiler.stop("GPU");
		}
		else {

			/* definitions */
			__m128i key_exp_128i[15], key_128i[2];

			/* define & start timer */
			AES_PROFILER aes_profiler(aes_hwni->buf_len);
			aes_profiler.start();

			if(key_len == 16){
				_ALIGNED(16) uchar key_alligned[16];
				memcpy(key_alligned, key, 16);
				key_128i[0] = _mm_load_si128((__m128i *) key_alligned);

				/* expand 128 bit key */
				key128_expand(key_128i, key_exp_128i);

				/* set limits of processing per thread */
				uint buf_len_mp = aes_hwni->buf_len / cpu_count;

				uchar* buf_in_mp = &aes_hwni->buf_in[0]
				                 + buf_len_mp* omp_get_thread_num();
				uchar* buf_out_mp = &aes_hwni->buf_out[0]
				                 + buf_len_mp* omp_get_thread_num();

				/* do encryption */
				for(uint i=0; i<buf_len_mp; i+=16)
					enc128_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);
			}

			else if(key_len == 32){
				_ALIGNED(32) uchar key_alligned[32];
				memcpy(key_alligned, key, 32);
				key_128i[0] = _mm_load_si128((__m128i *) key_alligned);
				key_128i[1] = _mm_load_si128((__m128i *) key_alligned + 1);

				/* expand 256 bit key */
				key256_expand(key_128i, key_exp_128i);

				/* set limits of processing per thread */
				uint buf_len_mp = aes_hwni->buf_len / cpu_count;
				uchar* buf_in_mp = &aes_hwni->buf_in[0]
				                 + buf_len_mp* omp_get_thread_num();
				uchar* buf_out_mp = &aes_hwni->buf_out[0]
				                 + buf_len_mp* omp_get_thread_num();

				/* do encryption */
				for(uint i=0; i<buf_len_mp; i+=16)
					enc256_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);
			}

			/* stop timer */
			aes_profiler.stop("CPU");
		}
	}
}


/*******************************************************
*	Function: decrypt
*******************************************************/
void AES_HYBRID::decrypt(){

	/* not implemented */
}

