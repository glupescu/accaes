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

#define CL_VAR_HOST int
#define CL_VAR_DEVICE cl_int
#define CL_VAR_KERNEL uint

/*******************************************************
*	CLASS AES_GPU functions
*******************************************************/

/* constructor */
AES_GPU::AES_GPU(uchar* buf_in, uchar* buf_out, uint buf_len,
				uchar* key, uint key_len, string aes_method,
				cl_uint usr_device_id) :
		AES_BASE(buf_in, buf_out, buf_len, key, key_len, aes_method){

		/* attempt to init gpu
		 * query platform and devices, check ids
		 * compile kernels for the chosen GPU
		 */
		init_gpu(usr_device_id);
	}

extern void key128_expand(__m128i key[], __m128i keyexp[]);
extern void key256_expand(__m128i key[], __m128i keyexp[]);

/*******************************************************
*	Function: expand_keys
*	Info: expand keys using AESNI CPU acceleration
*******************************************************/
void expand_keys(uchar* key_exp, int* rounds,
		unsigned char* key, uint key_len)
{
	__m128i key_exp_128i[15], key_128i[2];

	switch (key_len)
	{
		case 16: *rounds = 11; break;
		case 32: *rounds = 15; break;
	}

	if(key_len == 16){
			_ALIGNED(16) uchar key_alligned[16];
			memcpy(key_alligned, key, 16);
			key_128i[0] = _mm_load_si128((__m128i *) key_alligned);

			/* expand 128 bit key */
			key128_expand(key_128i, key_exp_128i);

			/* copy back */
			memcpy(key_exp, key_exp_128i, 16*15);
	}
	else if(key_len == 32){
			_ALIGNED(32) uchar key_alligned[32];
			memcpy(key_alligned, key, 32);
			key_128i[0] = _mm_load_si128((__m128i *) key_alligned);
			key_128i[1] = _mm_load_si128((__m128i *) key_alligned + 1);

			/* expand 256 bit key */
			key256_expand(key_128i, key_exp_128i);

			/* copy back */
			memcpy(key_exp, key_exp_128i, 16*15);
	}
}

/*******************************************************
*	Function: print_cl_errstring
*******************************************************/
const char* print_cl_errstring(cl_int err) {
switch (err) {
	case CL_SUCCESS:                     	return  "Success!";
	case CL_DEVICE_NOT_FOUND:               return  "Device not found.";
	case CL_DEVICE_NOT_AVAILABLE:           return  "Device not available";
	case CL_COMPILER_NOT_AVAILABLE:         return  "Compiler not available";
	case CL_MEM_OBJECT_ALLOCATION_FAILURE:  return  "Memory object alloc fail";
	case CL_OUT_OF_RESOURCES:               return  "Out of resources";
	case CL_OUT_OF_HOST_MEMORY:             return  "Out of host memory";
	case CL_PROFILING_INFO_NOT_AVAILABLE:   return  "Profiling information N/A";
	case CL_MEM_COPY_OVERLAP:               return  "Memory copy overlap";
	case CL_IMAGE_FORMAT_MISMATCH:          return  "Image format mismatch";
	case CL_IMAGE_FORMAT_NOT_SUPPORTED:     return  "Image format no support";
	case CL_BUILD_PROGRAM_FAILURE:          return  "Program build failure";
	case CL_MAP_FAILURE:                    return  "Map failure";
	case CL_INVALID_VALUE:                  return  "Invalid value";
	case CL_INVALID_DEVICE_TYPE:            return  "Invalid device type";
	case CL_INVALID_PLATFORM:               return  "Invalid platform";
	case CL_INVALID_DEVICE:                 return  "Invalid device";
	case CL_INVALID_CONTEXT:                return  "Invalid context";
	case CL_INVALID_QUEUE_PROPERTIES:       return  "Invalid queue properties";
	case CL_INVALID_COMMAND_QUEUE:          return  "Invalid command queue";
	case CL_INVALID_HOST_PTR:               return  "Invalid host pointer";
	case CL_INVALID_MEM_OBJECT:             return  "Invalid memory object";
	case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:return  "Invalid image format desc";
	case CL_INVALID_IMAGE_SIZE:             return  "Invalid image size";
	case CL_INVALID_SAMPLER:                return  "Invalid sampler";
	case CL_INVALID_BINARY:                 return  "Invalid binary";
	case CL_INVALID_BUILD_OPTIONS:          return  "Invalid build options";
	case CL_INVALID_PROGRAM:                return  "Invalid program";
	case CL_INVALID_PROGRAM_EXECUTABLE:     return  "Invalid program exec";
	case CL_INVALID_KERNEL_NAME:            return  "Invalid kernel name";
	case CL_INVALID_KERNEL_DEFINITION:      return  "Invalid kernel definition";
	case CL_INVALID_KERNEL:                 return  "Invalid kernel";
	case CL_INVALID_ARG_INDEX:              return  "Invalid argument index";
	case CL_INVALID_ARG_VALUE:              return  "Invalid argument value";
	case CL_INVALID_ARG_SIZE:               return  "Invalid argument size";
	case CL_INVALID_KERNEL_ARGS:            return  "Invalid kernel arguments";
	case CL_INVALID_WORK_DIMENSION:         return  "Invalid work dimension";
	case CL_INVALID_WORK_GROUP_SIZE:        return  "Invalid work group size";
	case CL_INVALID_WORK_ITEM_SIZE:         return  "Invalid work item size";
	case CL_INVALID_GLOBAL_OFFSET:          return  "Invalid global offset";
	case CL_INVALID_EVENT_WAIT_LIST:        return  "Invalid event wait list";
	case CL_INVALID_EVENT:                  return  "Invalid event";
	case CL_INVALID_OPERATION:              return  "Invalid operation";
	case CL_INVALID_GL_OBJECT:              return  "Invalid OpenGL object";
	case CL_INVALID_BUFFER_SIZE:            return  "Invalid buffer size";
	case CL_INVALID_MIP_LEVEL:              return  "Invalid mip-map level";
	default:                                return  "Unknown";
    }
}

/*******************************************************
*	Function: error log
*******************************************************/
void errorLog(cl_program program, cl_device_id device)
{
	char* build_log;
	size_t log_size;

	/* first call to know the proper size */
	clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG,
			0, NULL, &log_size);
	build_log = new char[log_size+1];

	/* Second call to get the log */
	clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG,
			log_size, build_log, NULL);
	build_log[log_size] = '\0';
	printf("%s",build_log);
}

/*******************************************************
*	Function: check
*******************************************************/
int check(int cuerr){

	if(cuerr != CL_SUCCESS){
		printf("\n%s\n", print_cl_errstring(cuerr));
		return 1;
    }
	return 0;
}

/*******************************************************
*	Function: check
*******************************************************/
int check(int cuerr, cl_program program, cl_device_id device){

     if(cuerr != CL_SUCCESS){
		printf("\n%s\n", print_cl_errstring(cuerr));
		errorLog(program, device);
		return 1;
     	}

	return 0;
}

/*******************************************************
*	Function: getSrcCode
*	Info: read source code from file, dynamic compilation
*******************************************************/
void getSrcCode(const char* filename, string& source)
{
   string line;
   ifstream in(filename);
   while(getline(in, line))
		source += line + "\n";
}

/*******************************************************
*	Function: init_gpu
*	Info: prepare OpenCL runtime, dynamic compilation
*******************************************************/
void AES_GPU::init_gpu(cl_uint usr_device_id)
{
	/* control execution */
	cl_long clDeviceMaxComputeUnits;
	CL_ComputeDevice dev_gpu;

	char clStrInfo[MAX_STR_SIZE];
	cl_uint cl_num_platforms;
	cl_num_devices = 0;

	clGetPlatformIDs(MAX_PLATFORMS, cl_platforms, &cl_num_platforms);;

	/* Platform name */
	clGetPlatformInfo(cl_platforms[0],
			CL_PLATFORM_NAME,
			sizeof(char)* MAX_STR_SIZE,
			clStrInfo, NULL);

	/* Get device pointers, filter by GPU type */
	clGetDeviceIDs(cl_platforms[0],
		CL_DEVICE_TYPE_GPU,
		MAX_DEVICE_COUNT,
		cl_devices,
		&cl_num_devices);

	DIE(usr_device_id >= cl_num_devices, "Invalid CL platform selected");
	printf("[%d/%d]", usr_device_id, cl_num_devices);

	/* GPU id selected */
	dev_gpu.dev_id = cl_devices[usr_device_id];

	/* save device name */
	clGetDeviceInfo(dev_gpu.dev_id, CL_DEVICE_NAME,
		sizeof(char) * MAX_STR_SIZE, clStrInfo, NULL);

	printf(" [%s] ", clStrInfo);
	dev_gpu.info_name = clStrInfo;


	/* get info on architecture MAX_COMPUTE_UNITS */
	clGetDeviceInfo(dev_gpu.dev_id,
		CL_DEVICE_MAX_COMPUTE_UNITS,
		sizeof(cl_long), &clDeviceMaxComputeUnits, NULL);

	printf("[CU %ld]\n", clDeviceMaxComputeUnits);

	/* create context for current gpu */
	dev_gpu.dev_context = clCreateContext (NULL, 1,
		&dev_gpu.dev_id, NULL, NULL, NULL);

	/* create queue for current gpu */
	dev_gpu.dev_cmd_queue = clCreateCommandQueue (
		dev_gpu.dev_context,
		dev_gpu.dev_id, 0, NULL);

	/* create queue for current gpu */
	dev_gpu.dev_cmd_queue_io = clCreateCommandQueue (
		dev_gpu.dev_context,
		dev_gpu.dev_id, 0, NULL);

	/* create queue for current gpu */
	dev_gpu.dev_cmd_queue_iow = clCreateCommandQueue (
		dev_gpu.dev_context,
		dev_gpu.dev_id, 0, NULL);

	/* build OPENCL program against current device */
	cl_int err;
	const char* cstr_source = NULL;
	string source;
	getSrcCode("kernel.cl", source);
	cstr_source = source.c_str();

	dev_gpu.dev_program = clCreateProgramWithSource(
				dev_gpu.dev_context, 1, &cstr_source, NULL, &err);
	check(err, dev_gpu.dev_program, dev_gpu.dev_id);

	check(clBuildProgram(dev_gpu.dev_program, 1,
					&dev_gpu.dev_id, NULL, NULL, NULL));

	/* kernels AES128 */
	dev_gpu.dev_kernel_enc128 = clCreateKernel(
	dev_gpu.dev_program, "AES128_Enc", &err);
	check(err, dev_gpu.dev_program, dev_gpu.dev_id);

	dev_gpu.dev_kernel_dec128 = clCreateKernel(
	dev_gpu.dev_program, "AES128_Dec", &err);
	check(err, dev_gpu.dev_program, dev_gpu.dev_id);

	/* kernels AES256 */
	dev_gpu.dev_kernel_enc256 = clCreateKernel(
	dev_gpu.dev_program, "AES256_Enc", &err);
	check(err, dev_gpu.dev_program, dev_gpu.dev_id);

	dev_gpu.dev_kernel_dec256 = clCreateKernel(
	dev_gpu.dev_program, "AES256_Dec", &err);
	check(err, dev_gpu.dev_program, dev_gpu.dev_id);

	/* save device to list of devives */
	this->dev_gpu = dev_gpu;
}


/*******************************************************
*	Function: encrypt_overlap
*	Info: encryption with I/O OVERLAP
*******************************************************/

void AES_GPU::encrypt_overlap()
{
	int rounds = 0;
		//uchar key_exp[15* 16];
		uchar* key_exp = new uchar[15*16];

		if(key_len == 16)
			dev_gpu.dev_kernel_sel = dev_gpu.dev_kernel_enc128;
		else if(key_len == 32)
			dev_gpu.dev_kernel_sel = dev_gpu.dev_kernel_enc256;

		/* expand keys using AESNI CPU acceleration */
		expand_keys(key_exp, &rounds, key, key_len);

		dev_gpu.buffer_keys = clCreateBuffer(
				dev_gpu.dev_context,
				CL_MEM_READ_ONLY,
				rounds* 16* sizeof(char), NULL, NULL);

		/* write keys */
		clEnqueueWriteBuffer(dev_gpu.dev_cmd_queue,
				dev_gpu.buffer_keys,
				CL_FALSE, 0, rounds* 16* sizeof(char), key_exp, 0, 0, 0);

		/* allocate memory INPUT - device RAM/VRAM, OpenCL handled */
		cl_mem buffer_gpu[GPU_BUF_NUM];

		for(int i=0; i<GPU_BUF_NUM; i++)
			buffer_gpu[i] = clCreateBuffer(
					dev_gpu.dev_context,
					CL_MEM_READ_WRITE,
					GPU_BUF_ALLOC_SIZE *sizeof(char), NULL, NULL);

		cl_event event_exec[GPU_BUF_NUM];
		cl_event event_io[GPU_BUF_NUM];

		size_t offset = 0;
		int BUF_i = 0;
		int num_it = buf_len / GPU_BUF_ALLOC_SIZE;

		size_t global_work = GPU_BUF_ALLOC_SIZE / 16;
		size_t threads = 128;

		for(int i=0; i<num_it; i++)
		{
			/* BUFFER INPUT, to be encrypted */
			check(clSetKernelArg(dev_gpu.dev_kernel_sel, 0,
					sizeof(cl_mem),	(void*)&buffer_gpu[BUF_i]));
			/* BUFFER KEYS, used in encryption */
			check(clSetKernelArg(dev_gpu.dev_kernel_sel, 1,
					sizeof(cl_mem),	(void*)&dev_gpu.buffer_keys));

			if(BUF_i == (GPU_BUF_NUM - 1))
				clEnqueueWriteBuffer(dev_gpu.dev_cmd_queue_iow,
						buffer_gpu[BUF_i], CL_TRUE, 0,
						GPU_BUF_ALLOC_SIZE *sizeof(char),
						buf_in + offset, 0, 0, &event_io[BUF_i]);
			else
				clEnqueueWriteBuffer(dev_gpu.dev_cmd_queue_iow,
						buffer_gpu[BUF_i], CL_FALSE, 0,
						GPU_BUF_ALLOC_SIZE *sizeof(char),
						buf_in + offset, 0, 0, &event_io[BUF_i]);

			check(clEnqueueNDRangeKernel(dev_gpu.dev_cmd_queue,
					dev_gpu.dev_kernel_sel, 1, NULL, &global_work,
				&threads, 1, &event_io[BUF_i], &event_exec[BUF_i]));

			if (i == (num_it - 1))
				clEnqueueReadBuffer(dev_gpu.dev_cmd_queue_io,
						buffer_gpu[BUF_i], CL_TRUE, 0,
						GPU_BUF_ALLOC_SIZE *sizeof(char),
						buf_out + offset, 1, &event_exec[BUF_i], 0);
			else if(BUF_i == (GPU_BUF_NUM - 1))
				clEnqueueReadBuffer(dev_gpu.dev_cmd_queue_io,
						buffer_gpu[BUF_i], CL_TRUE, 0,
						GPU_BUF_ALLOC_SIZE *sizeof(char),
						buf_out + offset, 1, &event_exec[BUF_i], 0);
			else
				clEnqueueReadBuffer(dev_gpu.dev_cmd_queue_io,
						buffer_gpu[BUF_i], CL_FALSE, 0,
						GPU_BUF_ALLOC_SIZE *sizeof(char),
						buf_out + offset, 1, &event_exec[BUF_i], 0);

			offset += GPU_BUF_ALLOC_SIZE;

			BUF_i++;
			BUF_i = BUF_i % GPU_BUF_NUM;
		}

		/* release all OpenCL memory objects */
		for(int i=0; i<GPU_BUF_NUM; i++)
			clReleaseMemObject(buffer_gpu[i]);
		clReleaseMemObject(dev_gpu.buffer_keys);
}

/*******************************************************
*	Function: encrypt_no_overlap
*	Info: plain encryption, without I/O OVERLAP
*******************************************************/
void AES_GPU::encrypt_no_overlap()
{
	/* allocate memory INPUT - device RAM/VRAM, OpenCL handled */
	cl_mem buffer_gpu;

	/* variables for keys */
	int rounds = 0;
	uchar* key_exp = new uchar[15*16];

	if(key_len == 16)
		dev_gpu.dev_kernel_sel = dev_gpu.dev_kernel_enc128;
	else if(key_len == 32)
		dev_gpu.dev_kernel_sel = dev_gpu.dev_kernel_enc256;

	/* expand keys using AESNI CPU acceleration */
	expand_keys(key_exp, &rounds, key, key_len);

	dev_gpu.buffer_keys = clCreateBuffer(
			dev_gpu.dev_context,
			CL_MEM_READ_ONLY,
			rounds* 16* sizeof(char), NULL, NULL);

	/* write keys */
	clEnqueueWriteBuffer(dev_gpu.dev_cmd_queue,
			dev_gpu.buffer_keys,
			CL_FALSE, 0, rounds* 16* sizeof(char), key_exp, 0, 0, 0);

	/* create limited buffer in VRAM */
	buffer_gpu = clCreateBuffer(dev_gpu.dev_context,
					CL_MEM_READ_WRITE,
					GPU_BUF_ALLOC_SIZE *sizeof(char), NULL, NULL);

	size_t offset = 0;
	int num_it = (buf_len / GPU_BUF_ALLOC_SIZE);

	size_t global_work = GPU_BUF_ALLOC_SIZE / 16;
	size_t threads = 128;

	/* BUFFER INPUT, to be encrypted */
	check(clSetKernelArg(dev_gpu.dev_kernel_sel, 0,
			sizeof(cl_mem),	(void*)&buffer_gpu));
	/* BUFFER KEYS, used in encryption */
	check(clSetKernelArg(dev_gpu.dev_kernel_sel, 1,
			sizeof(cl_mem),	(void*)&dev_gpu.buffer_keys));

	/****************************************************/
	/* STEP - write, process, read */
	/****************************************************/
	for(int i=0; i<num_it; i++)
	{
		clEnqueueWriteBuffer(dev_gpu.dev_cmd_queue,
				buffer_gpu, CL_TRUE, 0, GPU_BUF_ALLOC_SIZE *sizeof(char),
				buf_in + offset, 0, 0, 0);

		check(clEnqueueNDRangeKernel(dev_gpu.dev_cmd_queue,
				dev_gpu.dev_kernel_sel, 1, NULL, &global_work,
			&threads, 0, NULL, NULL));

		clEnqueueReadBuffer(dev_gpu.dev_cmd_queue,
				buffer_gpu, CL_TRUE,
				0, GPU_BUF_ALLOC_SIZE *sizeof(char), buf_out + offset, 0, 0, 0);

		offset += GPU_BUF_ALLOC_SIZE;
	}

	/* release all OpenCL memory objects */
	clReleaseMemObject(buffer_gpu);
	clReleaseMemObject(dev_gpu.buffer_keys);

}

/*******************************************************
*	Function: desctructor, ~AES_GPU
*	Info: plain encryption, without I/O OVERLAP
*******************************************************/
AES_GPU::~AES_GPU()
{
	clReleaseKernel(dev_gpu.dev_kernel_dec128);
	clReleaseKernel(dev_gpu.dev_kernel_dec256);
	clReleaseKernel(dev_gpu.dev_kernel_enc128);
	clReleaseKernel(dev_gpu.dev_kernel_enc256);

	clReleaseProgram(dev_gpu.dev_program);
	clReleaseContext(dev_gpu.dev_context);
}

/*******************************************************
*	Function: encrypt
*******************************************************/
void AES_GPU::encrypt()
{
	/* gpu encryption with I/O overlap */
	encrypt_overlap();

	/* gpu encryption without I/O overlap */
	// encrypt_no_overlap();
}

/*******************************************************
*	Function: decrypt
*******************************************************/
void AES_GPU::decrypt()
{
	/* no decryption implemented */
}
