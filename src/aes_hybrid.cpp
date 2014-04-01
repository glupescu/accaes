#include "main.h"


/*	plain_gpu		plain_cpu
 * 		\/			\/
 * 		*-------------------------------*
 * 		*	WORK	|		WORK		*
 * 		*	GPU		|		CPU			*
 * 		*	AES		|		AES			*
 * 		*-------------------------------*
 */

AES_HYBRID::AES_HYBRID(uchar* buf_in, uchar* buf_out, uint buf_len,
		uchar* key, string aes_method, AES_OPTIONS aes_options) :
		AES_BASE(buf_in, buf_out, buf_len, key, aes_method){

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
			buf_len_gpu	 = buf_len * ((float)cl_user_splits[i] / (float)100);

			/* CPU has less work */
			buf_len_hwni -= buf_len_gpu;

			/* init and push GPU */
			aes_gpus[i] = new AES_GPU(buf_in_gpu, buf_out_gpu, buf_len_gpu,
					key, aes_method, cl_user_ids[i]);
		}

		/* computing space for CPU left space to work on */
		buf_in_hwni		=	buf_in_gpu + buf_len_gpu;
		buf_out_hwni	=	buf_out_gpu + buf_len_gpu;

		/* init CPU */
		aes_hwni = new AES_HWNI(buf_in_hwni, buf_out_hwni, buf_len_hwni,
						key, aes_method);
	}

/*******************************************************
*	Encrypt Hybrid
*******************************************************/
#define OPENMP_CPU_THREADS 2

void AES_HYBRID::encrypt(){

	omp_set_num_threads(OPENMP_CPU_THREADS + cl_user_ids.size());
	#pragma omp parallel
	{
		if(omp_get_thread_num() >= OPENMP_CPU_THREADS){
			uint tid = omp_get_thread_num();
			AES_PROFILER aes_profiler(aes_gpus[tid - OPENMP_CPU_THREADS]->buf_len);

			/* start timer */
			aes_profiler.start();

			/* do encryption & time it */
			aes_gpus[tid - OPENMP_CPU_THREADS]->encrypt();

			/* stop timer */
			cout << "GPU ";
			aes_profiler.stop();
		}
		else {
			AES_PROFILER aes_profiler(aes_hwni->buf_len);

			/* start timer */
			aes_profiler.start();

			/* definitions */
			__m128i key_exp_128i[11], key_128i;
			_ALIGNED(16) uchar key_alligned[16];

			/* allign memory */
			memcpy(key_alligned, key, 16);
			key_128i = _mm_load_si128((__m128i *) key_alligned);

			/* expand the key */
			key_expand(key_128i, key_exp_128i);

			/* set limits of processing per thread */
			uint buf_len_mp = aes_hwni->buf_len / OPENMP_CPU_THREADS;
			uchar* buf_in_mp = &aes_hwni->buf_in[0]
			                 + buf_len_mp* omp_get_thread_num();
			uchar* buf_out_mp = &aes_hwni->buf_out[0]
			                 + buf_len_mp* omp_get_thread_num();

			/* do encryption */
			for(uint i=0; i<buf_len_mp; i+=16)
				encrypt_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);

			/* stop timer */
			cout << "CPU ";
			aes_profiler.stop();
		}
	}
}


/*******************************************************
*	Decrypt Hybrid
*******************************************************/
void AES_HYBRID::decrypt(){

	omp_set_num_threads(OPENMP_CPU_THREADS + cl_user_ids.size());
	#pragma omp parallel
	{
		if(omp_get_thread_num() >= OPENMP_CPU_THREADS){
			uint tid = omp_get_thread_num();

			/* do encryption & time it */
			aes_gpus[tid - OPENMP_CPU_THREADS]->decrypt();
		}
		else {

			/* definitions */
			__m128i key_exp_128i[11], key_128i;
			_ALIGNED(16) uchar key_alligned[16];

			/* allign memory */
			memcpy(key_alligned, key, 16);
			key_128i = _mm_load_si128((__m128i *) key_alligned);

			/* expand the key */
			key_expand(key_128i, key_exp_128i);

			/* set limits of processing per thread */
			uint buf_len_mp = aes_hwni->buf_len / OPENMP_CPU_THREADS;
			uchar* buf_in_mp = &aes_hwni->buf_in[0] +
					buf_len_mp* omp_get_thread_num();
			uchar* buf_out_mp = &aes_hwni->buf_out[0]+
					buf_len_mp* omp_get_thread_num();

			/* do encryption */
			for(uint i=0; i<buf_len_mp; i+=16)
				decrypt_hwni(buf_in_mp+i, buf_out_mp+i, key_exp_128i);
		}
	}
}

