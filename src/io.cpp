#include "main.h"
#include <string>
#include "boost/program_options.hpp"

using namespace std;
using namespace boost::program_options;

/*******************************************************
*	Pars Cmd Options
*******************************************************/
void io_parse_options(int argc, char** argv, AES_OPTIONS &aes_options)
{
	/* defaults */
	aes_options.ecb_ccb				= ECB;
	aes_options.enc_dec				= ENCRYPT;
	aes_options.perf_mode			= false;
	aes_options.file_in				= "in.txt";
	aes_options.file_out			= "out.txt";
	aes_options.key_in				= "keyin.txt";
	aes_options.key_out				= "keyout.txt";
	aes_options.processing_method	= CPU_HWNI;
	aes_options.num_iterations		= 3;

	/* declare the supported options */
	options_description desc("Allowed options");
	desc.add_options()
	/* enc/dec methods */
	/*("ecb", "do AES ECB")*/
    ("dec,d", "do AES decryption, default encryption")

    /* file/key I/O */
	("in,i",		value<string>(),	"input file")
	("out,o",		value<string>(),	"output file")
	("buf,b", 		value<int>(), "generate MB data for I/O")
	/* TODO */
	/*("keyout",		value<string>(),	"key file out") */

	/* processing methods */
	("cpu,c",		"CPU AESNI multicore")
	("gpu,g",		value<string>(), "GPU OpenCL, CL dev ids")
	("split,s",		value<string>(), "OpenCL % split work, separate by comma")

	/* trace mode */
    /*("it,t", value<int>(), "number of iterations (perf mode)") */

    /* display help & exit */
	("help,h", "produce help message")
	("vers,v", "version number");

	variables_map vm;
	store(parse_command_line(argc, argv, desc), vm);
	notify(vm);

	try{
		/* ECB or CCB settings */
		if(vm.count("ecb"))
			aes_options.ecb_ccb = ECB;
		else if(vm.count("ccb"))
			aes_options.ecb_ccb = CCB;

		/* encrypt or decrypt */
		if(vm.count("dec"))
			aes_options.enc_dec = DECRYPT;

		/* perf mode */
		if(vm.count("perf"))
			aes_options.perf_mode = true;
		if(vm.count("it"))
				aes_options.num_iterations = vm["it"].as<int>();
		if(vm.count("buf"))
				aes_options.buf_len = vm["buf"].as<int>() *1024 *1000;

		/* input/output files */
		if(vm.count("in"))
			aes_options.file_in = vm["in"].as<string>();
		if(vm.count("out"))
			aes_options.file_out = vm["out"].as<string>();
		if(vm.count("keyin"))
			aes_options.key_in = vm["keyin"].as<string>();

		/* processing method */
		if(vm.count("cpu"))
			aes_options.processing_method = CPU_HWNI;
		if(vm.count("gpu")){
			istringstream ss(vm["gpu"].as<string>());
			string token;
			while(std::getline(ss, token, ','))
				aes_options.cl_device_ids.push_back(atoi(token.c_str()));

			/* if no device specified, we use firts device */
			if(aes_options.cl_device_ids.size() == 0)
				aes_options.cl_device_ids.push_back(0);

			/* select processing mode */
			if(aes_options.processing_method == CPU_HWNI)
				aes_options.processing_method = HYBRID; /* 1CPU + NGPU */
			else if(aes_options.cl_device_ids.size() > 1)
				aes_options.processing_method = HYBRID; /* NGPU */
			else
				aes_options.processing_method = GPU; /* 1GPU */
		}

		if(vm.count("split")){
			istringstream ss(vm["split"].as<string>());
			string token;
			while(std::getline(ss, token, ','))
				aes_options.cl_device_splits.push_back(atoi(token.c_str()));
		}
		else {
			/* safeguard in case options are not provided, each GPU 10% */
			for(size_t i=0; i<aes_options.cl_device_ids.size(); i++)
				aes_options.cl_device_splits.push_back(10);
		}

		/* display help */
		if (vm.count("help")){
			cout << desc << "\n";
			exit(0);
		}
		if(vm.count("vers"))
		{
			cout << "ACCSEC, Lupescu Grigore, "__DATE__ << endl;
			exit(0);
		}
	}catch(error& e)
	{
		cerr << "ERROR: " << e.what() << endl << endl;
		cerr << desc << endl;
	}
}

/*******************************************************
*	Prepare input
*******************************************************/

void io_IN(unsigned char* &buf_in,
		unsigned char* &buf_out,
		AES_OPTIONS aes_opt)
{
	unsigned buf_len = aes_opt.buf_len;

	/* allocate buf_in memory and read/generare */
	if(aes_opt.file_in.size() == 0)
		io_read_file(buf_in, buf_len, aes_opt.file_in.c_str());
	else {
		buf_in = new unsigned char[buf_len];
		DIE(buf_in == NULL, "Could not allocate memory buf_out\n");

		/* generate data */
		uninitialized_fill_n(buf_in, buf_len, 1);
	}

	/* allocate buf_out memory */
	buf_out = new uchar[buf_len];
	DIE(buf_out == NULL, "Could not allocate memory buf_out\n");
}


/*******************************************************
*	Validate/write output
*******************************************************/

void io_OUT(unsigned char * &buf_in,
		unsigned char * &buf_out,
		AES_OPTIONS aes_opt)
{
	unsigned buf_len = aes_opt.buf_len;
	//uchar key[16] = KEY_1;

	if(aes_opt.file_out.size() == 0)
		io_write_file(buf_out, buf_len, aes_opt.file_out.c_str());
		else {

			///AES_OPENSSL aes_validate(buf_in, buf_in, buf_len,
			//				key, "AES_OPENSSL");
			//aes_validate.encrypt();

			//for(int i=0; i<buf_len; i++)
			//	if(buf_in[i] != buf_out[i]){
			//		cout<< i << endl;
			//		break;
			//	}
		}

	delete[] buf_in;
	delete[] buf_out;
}

/*******************************************************
*	Write binary file
*******************************************************/
void io_write_file(unsigned char *buffer, unsigned size, const char* filename)
{
	FILE *fp;

	/* open file & check pointer */
	DIE((fp=fopen(filename, "wb"))==NULL, "Cannot open file !!!\n");

	/* write size num data and check written amount */
	DIE(fwrite(buffer, sizeof(unsigned char), size, fp) != size,
			"File write error !!!\n");

	/* free file handler */
	fclose(fp);
}

/*******************************************************
*	Read binary file
*******************************************************/
void io_read_file(unsigned char*& buffer, unsigned &size, const char* filename)
{
	unsigned int i=0;
	FILE *file;

	/* Open file */
	file = fopen(filename, "rb");
	DIE(!file, "Unable to open file !!! \n");

	/* Get file length */
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);

	/* Allocate memory */
	buffer = new uchar[size + 1];
	DIE(!buffer, "Memory allocation failed !!!\n");

	/* Read file char by char */
	while(i < size){
		buffer[i] = fgetc(file);
	    i++;
	}

	/* Read file contents into buffer */
	fclose(file);
}

/*******************************************************
*	Display data as HEX from buffer
*******************************************************/
void io_display_hex(unsigned char* buffer, unsigned size)
{
	for (uint c=0; c<size; c++)
	{
	     printf("%.2X ", (int)buffer[c]);

	     /* put an extra space between every 4 bytes */
	     if (c % 4 == 3)
	     {
		 printf(" ");
	     }

	     /* Display 16 bytes per line */
	     if (c % 16 == 15)
	     {
		 printf("\n");
	     }
	}
	/* Add an extra line feed for good measure */
	printf("\n\n");
}

/*******************************************************
*	Display data as ASCII from buffer
*******************************************************/
void io_display_ascii(unsigned char* buffer, unsigned size)
{
	for (uint c=0; c<size; c++)
		printf("%c", buffer[c]);

	/* Add an extra line feed for good measure */
	printf("\n\n");
}
