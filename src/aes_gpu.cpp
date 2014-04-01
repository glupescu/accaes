#include "main.h"

#define CL_SIZE_1MB (1000*1024)
#define CL_VAR_ALLOC_SIZE (4096 * 1024)
#define CL_VAR_HOST int
#define CL_VAR_DEVICE cl_int
#define CL_VAR_KERNEL uint

/*******************************************************
*	CLASS AES_GPU functions
*******************************************************/

/* constructor */
AES_GPU::AES_GPU(uchar* buf_in, uchar* buf_out, uint buf_len,
				uchar* key, string aes_method,
				cl_uint usr_device_id) :
		AES_BASE(buf_in, buf_out, buf_len, key, aes_method){

		/* attempt to init gpu
		 * query platform and devices, check ids
		 * compile kernels for the chosen GPU
		 */
		init_gpu(usr_device_id);
	}

unsigned char AES_SBox[256] =
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
   0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
   0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
   0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
   0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
   0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
   0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
   0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
   0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
   0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
   0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
   0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
   0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
   0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
   0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
   0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char Rcon[256] =
{
	0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
	0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
	0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
	0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
	0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25,
	0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A,
	0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
	0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6,
	0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF,
	0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61,
	0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC,
	0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01,
	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,
	0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E,
	0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3,
	0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4,
	0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94,
	0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8,
	0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
	0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35,
	0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91,
	0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F,
	0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D,
	0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
	0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
	0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA,
	0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD,
	0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66,
	0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D
};


void ComputeRoundKeys(unsigned char** roundKeys, int* rounds, size_t size,
	unsigned char* key)
{
	unsigned char rotWord[4];

	/* Size in bytes */
	switch (size)
	{
		case 16: *rounds = 11; break;
		case 24: *rounds = 12; break;
		case 32: *rounds = 15; break;
		default:
			printf("Key be 16, 24 or 32 bytes\n");
			exit(1);
	}

	*roundKeys = new unsigned char[*rounds * 16];

	/*	first n bytes of the expanded key are simply the encryption key. */
	for (uint k = 0; k < size; k++)
		(*roundKeys)[k] = key[k];

	for (int k = 1; k < (*rounds) ; k++)
	{
		size_t offset = size + (k - 1) * 16; /* in bytes */

		/* calculate the rotated word */
		rotWord[0] = AES_SBox[(*roundKeys)[offset - 3]];
		rotWord[1] = AES_SBox[(*roundKeys)[offset - 2]];
		rotWord[2] = AES_SBox[(*roundKeys)[offset - 1]];
		rotWord[3] = AES_SBox[(*roundKeys)[offset - 4]];

		/* first word */
		(*roundKeys)[offset +  0] = (*roundKeys)[offset - 16] ^ rotWord[0] ^
			Rcon[k];
		(*roundKeys)[offset +  1] = (*roundKeys)[offset - 15] ^ rotWord[1];
		(*roundKeys)[offset +  2] = (*roundKeys)[offset - 14] ^ rotWord[2];
		(*roundKeys)[offset +  3] = (*roundKeys)[offset - 13] ^ rotWord[3];

		/* Second, third and forth words */
		((unsigned int *)(*roundKeys))[offset/4 + 1] =
			((unsigned int *)(*roundKeys))[offset/4 + 0] ^
			((unsigned int *)(*roundKeys))[offset/4 - 3];
		((unsigned int *)(*roundKeys))[offset/4 + 2] =
			((unsigned int *)(*roundKeys))[offset/4 + 1] ^
			((unsigned int *)(*roundKeys))[offset/4 - 2];
		((unsigned int *)(*roundKeys))[offset/4 + 3] =
			((unsigned int *)(*roundKeys))[offset/4 + 2] ^
			((unsigned int *)(*roundKeys))[offset/4 - 1];
	}
}

/*******************************************************
*	Error codes
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
*	Error log
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

int check(int cuerr){

	if(cuerr != CL_SUCCESS)
	{
		printf("\n%s\n", print_cl_errstring(cuerr));
		return 1;
    }
	return 0;
}

int check(int cuerr, cl_program program, cl_device_id device){

     if(cuerr != CL_SUCCESS)
	{
		printf("\n%s\n", print_cl_errstring(cuerr));
		errorLog(program, device);
		return 1;
     	}

	return 0;
}

void getSrcCode(const char* filename, string& source)
{
   string line;
   ifstream in(filename);
   while(getline(in, line))
		source += line + "\n";
}

void AES_GPU::init_gpu(cl_uint usr_device_id)
{
	/* control execution */
	cl_long clDeviceMaxComputeUnits;
	CL_ComputeDevice aes_gpu_current;

	char clStrInfo[MAX_STR_SIZE];
	cl_uint cl_num_platforms;
	cl_num_devices = 0;

	clGetPlatformIDs(MAX_PLATFORMS, cl_platforms, &cl_num_platforms);

	/* Platform name */
	clGetPlatformInfo(cl_platforms[1],
			CL_PLATFORM_NAME,
			sizeof(char)* MAX_STR_SIZE,
			clStrInfo, NULL);
	printf("[ %s ] ", clStrInfo);

	/* Get device pointers, filter by GPU type */
	clGetDeviceIDs(cl_platforms[1],
		CL_DEVICE_TYPE_GPU,
		MAX_DEVICE_COUNT,
		cl_devices,
		&cl_num_devices);

	DIE(usr_device_id >= cl_num_devices, "Invalid CL platform selected");
	printf("[%d/%d]", usr_device_id, cl_num_devices);

	/* GPU id selected */
	aes_gpu_current.dev_id = cl_devices[usr_device_id];

	/* save device name */
	clGetDeviceInfo(aes_gpu_current.dev_id, CL_DEVICE_NAME,
		sizeof(char) * MAX_STR_SIZE, clStrInfo, NULL);
	printf(" [%s] ", clStrInfo);
	aes_gpu_current.info_name = clStrInfo;

	/* get info on architecture MAX_COMPUTE_UNITS */
	clGetDeviceInfo(aes_gpu_current.dev_id,
		CL_DEVICE_MAX_COMPUTE_UNITS,
		sizeof(cl_long), &clDeviceMaxComputeUnits, NULL);
		printf("[CU %ld]\n", clDeviceMaxComputeUnits);

	/* create context for current gpu */
	aes_gpu_current.dev_context = clCreateContext (NULL, 1,
		&aes_gpu_current.dev_id, NULL, NULL, NULL);

	/* create queue for current gpu */
	aes_gpu_current.dev_cmd_queue = clCreateCommandQueue (
		aes_gpu_current.dev_context,
		aes_gpu_current.dev_id, 0, NULL);

	/* build OPENCL program against current device */
	cl_int err;
	const char* cstr_source = NULL;
	string source;
	getSrcCode("kernel.cl", source);
	cstr_source = source.c_str();

	aes_gpu_current.dev_program = clCreateProgramWithSource(
				aes_gpu_current.dev_context, 1, &cstr_source, NULL, &err);
	check(err, aes_gpu_current.dev_program, aes_gpu_current.dev_id);
	check(clBuildProgram(aes_gpu_current.dev_program, 1,
					&aes_gpu_current.dev_id, NULL, NULL, NULL));

	/* kernels encrypt and decrypt */
	aes_gpu_current.dev_kernel_enc_ecb = clCreateKernel(
	aes_gpu_current.dev_program, "AES_ECB_Encrypt", &err);
	aes_gpu_current.dev_kernel_dec_ecb = clCreateKernel(
	aes_gpu_current.dev_program, "AES_ECB_Decrypt", &err);
	check(err, aes_gpu_current.dev_program, aes_gpu_current.dev_id);

	/* save device to list of devives */
	aes_gpu_device = aes_gpu_current;
}

/*******************************************************
*	ENCRYPTION old
*******************************************************/
void AES_GPU::encrypt_old()
{
	int rounds = 0;
	unsigned char* roundKeys = NULL;

	size_t global_work = buf_len / 16;
	size_t threads = 128;

	ComputeRoundKeys(&roundKeys, &rounds, 16, key);

	/* allocate memory INPUT - device RAM/VRAM, OpenCL handled */
	aes_gpu_device.buffer_in = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_READ_ONLY,
			buf_len *sizeof(char), NULL, NULL);

	/* allocate memory OUTPUT - device RAM/VRAM, OpenCL hendled */
	aes_gpu_device.buffer_out = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_WRITE_ONLY,
			buf_len *sizeof(char), NULL, NULL);

	/* for zero copy CL_MEM_ALLOC_HOST_PTR | CL_MEM_READ_ONLY
	 allocate memory KEYS- device RAM/VRAM, OpenCL hendled
	 * TODO remove */
	aes_gpu_device.buffer_keys = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_READ_ONLY,
			rounds* 16* sizeof(char), NULL, NULL);


	/* For zero copy clcreate buffer must be
	 * CL_MEM_ALLOC_HOST_PTR | CL_MEM_READ_ONLY
	 */
	/*
	void* map_buffer_keys = (char*)clEnqueueMapBuffer(
	aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_keys,
			CL_TRUE, CL_MAP_WRITE, 0,
			rounds* 16* sizeof(char), 0, NULL, NULL, NULL);
	memcpy(map_buffer_keys, roundKeys, rounds* 16* sizeof(char));
	clEnqueueUnmapMemObject(aes_gpu_device.dev_cmd_queue,
			  aes_gpu_device.buffer_keys, map_buffer_keys, 0, NULL, NULL);
			  */


	/* write data to specified device address, OpenCL handled */
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_in, CL_FALSE, 0, buf_len *sizeof(char),
			buf_in, 0, 0, 0);

	/* write keys */
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_keys,
			CL_FALSE, 0, rounds* 16* sizeof(char), roundKeys, 0, 0, 0);

	/* BUFFER INPUT, to be encrypted */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 0,
			sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_in));
	/* BUFFER OUTPUT, encrypted */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 1,
			sizeof(cl_mem),  (void*)&aes_gpu_device.buffer_out));
	/* BUFFER KEYS, used in encryption */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 2,
			sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_keys));

	/* for tracing purposes */
	//struct timespec starttime;
	//struct timespec endtime;

	/* start GPU execution */
	//clock_gettime(CLOCK_REALTIME, &starttime);
	check(clEnqueueNDRangeKernel(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.dev_kernel_enc_ecb, 1, NULL, &global_work,
		&threads, 0, NULL, NULL));

	/* wait for GPU to finish */
	//check(clFinish(aes_gpu_device.dev_cmd_queue));
	//clock_gettime(CLOCK_REALTIME, &endtime);
	//cout << "[ GPU KERN ] " <<
	//		((double)((endtime.tv_sec * 1000000000) + endtime.tv_nsec)
	//		- ((starttime.tv_sec * 1000000000) + starttime.tv_nsec))/1000000
	//		<< "ms" << endl;

	/* read back to host memory from CL buffer */
	//clock_gettime(CLOCK_REALTIME, &starttime);
	clEnqueueReadBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_out, CL_TRUE,
			0, buf_len *sizeof(char), buf_out, 0, 0, 0);
	//clock_gettime(CLOCK_REALTIME, &endtime);
	//cout << "[ GPU OUT ] " <<
	//		((double)((endtime.tv_sec * 1000000000) + endtime.tv_nsec)
	//		- ((starttime.tv_sec * 1000000000) + starttime.tv_nsec))/1000000
	//		<< "ms" << endl;

	clReleaseMemObject(aes_gpu_device.buffer_in);
	clReleaseMemObject(aes_gpu_device.buffer_out);
	clReleaseMemObject(aes_gpu_device.buffer_keys);

}

/*******************************************************
*	ENCRYPTION new
*******************************************************/

#define GPU_BUF_SIZE (32* CL_SIZE_1MB)
#define GPU_BUF_NUM 3

void AES_GPU::encrypt()
{
	int rounds = 0;
	unsigned char* roundKeys = NULL;

	ComputeRoundKeys(&roundKeys, &rounds, 16, key);

	aes_gpu_device.buffer_keys = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_READ_ONLY,
			rounds* 16* sizeof(char), NULL, NULL);

	/* write keys */
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_keys,
			CL_FALSE, 0, rounds* 16* sizeof(char), roundKeys, 0, 0, 0);

	/* allocate memory INPUT - device RAM/VRAM, OpenCL handled */
	cl_mem buffer_gpu[GPU_BUF_NUM];

	for(int i=0; i<GPU_BUF_NUM; i++)
		buffer_gpu[i] = clCreateBuffer(
				aes_gpu_device.dev_context,
				CL_MEM_READ_WRITE,
				GPU_BUF_SIZE *sizeof(char), NULL, NULL);

	size_t offset = 0;
	int i_IN=1, i_OUT=0, i_RW=2;
	int num_it = (buf_len / GPU_BUF_SIZE) - 1;
	//cout << buf_len << " " << GPU_BUF_SIZE << " " << num_it << endl;

	size_t global_work = GPU_BUF_SIZE / 16;
	size_t threads = 128;

	/*************************************/
	/* STEP 1. enqW (CPU->GPU)           */
	/*************************************/
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			buffer_gpu[i_IN], CL_FALSE, 0, GPU_BUF_SIZE *sizeof(char),
			buf_in, 0, 0, 0);

	/****************************************************/
	/* STEP 2. proc (GPU->GPU) || enqR(GPU) & enqW(CPU) */
	/****************************************************/
	for(int i=0; i<num_it; i++)
	{
		/* BUFFER INPUT, to be encrypted */
		check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 0,
				sizeof(cl_mem),	(void*)&buffer_gpu[i_IN]));
		/* BUFFER OUTPUT, encrypted */
		check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 1,
				sizeof(cl_mem),  (void*)&buffer_gpu[i_OUT]));
		/* BUFFER KEYS, used in encryption */
		check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 2,
				sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_keys));

		check(clEnqueueNDRangeKernel(aes_gpu_device.dev_cmd_queue,
				aes_gpu_device.dev_kernel_enc_ecb, 1, NULL, &global_work,
			&threads, 0, NULL, NULL));

		clEnqueueReadBuffer(aes_gpu_device.dev_cmd_queue,
				buffer_gpu[i_OUT], CL_TRUE,
				0, GPU_BUF_SIZE *sizeof(char), buf_out + offset, 0, 0, 0);

		offset += GPU_BUF_SIZE;

		clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
				buffer_gpu[i_RW], CL_FALSE, 0, GPU_BUF_SIZE *sizeof(char),
				buf_in + offset, 0, 0, 0);

		i_IN++; i_OUT++; i_RW++;
		i_IN = i_IN%3;
		i_OUT = i_OUT%3;
		i_RW = i_RW%3;
	}

	/****************************************************/
	/* STEP 3. proc (GPU->GPU) & enqR (CPU->GPU)        */
	/****************************************************/

	/* BUFFER INPUT, to be encrypted */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 0,
			sizeof(cl_mem),	(void*)&buffer_gpu[i_IN]));
	/* BUFFER OUTPUT, encrypted */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 1,
			sizeof(cl_mem),  (void*)&buffer_gpu[i_OUT]));
	/* BUFFER KEYS, used in encryption */
	check(clSetKernelArg(aes_gpu_device.dev_kernel_enc_ecb, 2,
			sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_keys));

	check(clEnqueueNDRangeKernel(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.dev_kernel_enc_ecb, 1, NULL, &global_work,
		&threads, 0, NULL, NULL));

	clEnqueueReadBuffer(aes_gpu_device.dev_cmd_queue,
			buffer_gpu[i_OUT], CL_TRUE,
			0, GPU_BUF_SIZE *sizeof(char), buf_out + offset, 0, 0, 0);


	clReleaseMemObject(buffer_gpu[0]);
	clReleaseMemObject(buffer_gpu[1]);
	clReleaseMemObject(buffer_gpu[2]);
	clReleaseMemObject(aes_gpu_device.buffer_keys);

}


/*******************************************************
*	DECRYPTION
*******************************************************/
void AES_GPU::decrypt()
{
	int rounds = 0;
	unsigned char* roundKeys = NULL;

	size_t global_work = buf_len / 16;
	size_t threads = 32;

	ComputeRoundKeys(&roundKeys, &rounds, 16, key);

	/* allocate memory INPUT - device RAM/VRAM, OpenCL handled */
	aes_gpu_device.buffer_in = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_READ_ONLY,
			buf_len *sizeof(char), NULL, NULL);

	/* allocate memory OUTPUT - device RAM/VRAM, OpenCL hendled */
	aes_gpu_device.buffer_out = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_WRITE_ONLY,
			buf_len *sizeof(char), NULL, NULL);

	/* allocate memory KEYS- device RAM/VRAM, OpenCL hendled */
	aes_gpu_device.buffer_keys = clCreateBuffer(
			aes_gpu_device.dev_context,
			CL_MEM_READ_ONLY,
			rounds* 16* sizeof(char), NULL, NULL);

	/* write data to specified device address, OpenCL handled */
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_in, 1, 0, buf_len *sizeof(char),
			buf_in, 0, 0, 0);

	/* write keys */
	clEnqueueWriteBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_keys, 1, 0, rounds* 16* sizeof(char),
				roundKeys, 0, 0, 0);

	check(clSetKernelArg(aes_gpu_device.dev_kernel_dec_ecb, 0,
			sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_in));
	check(clSetKernelArg(aes_gpu_device.dev_kernel_dec_ecb, 1,
			sizeof(cl_mem),  (void*)&aes_gpu_device.buffer_out));
	check(clSetKernelArg(aes_gpu_device.dev_kernel_dec_ecb, 2,
			sizeof(cl_mem),	(void*)&aes_gpu_device.buffer_keys));

	/* start execution */
	check(clEnqueueNDRangeKernel(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.dev_kernel_dec_ecb, 1, NULL, &global_work,
		&threads, 0, NULL, NULL));


	/* wait for GPU to finish */
	//check(clFinish(aes_gpu_device.dev_cmd_queue));tarttime.tv_nsec));

	/* read back to host memory from CL buffer */
	clEnqueueReadBuffer(aes_gpu_device.dev_cmd_queue,
			aes_gpu_device.buffer_out,
			CL_TRUE, 0, buf_len* sizeof(char), buf_out, 0, 0, 0);

	clReleaseMemObject(aes_gpu_device.buffer_in);
	clReleaseMemObject(aes_gpu_device.buffer_out);
	clReleaseMemObject(aes_gpu_device.buffer_keys);

}
