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
#include <string>
#include <getopt.h>
#include <sstream>

using namespace std;

/*******************************************************
*	Function: op_check_options
*******************************************************/
bool op_check_options(AES_OPTIONS &aes_options)
{
	if(aes_options.cl_device_ids.size() 
			!= aes_options.cl_device_splits.size())
	{
		printf("invalid");
		return false;
	}

	return true;
}

/*******************************************************
*	Function: io_parse_options
*******************************************************/
void io_parse_options(int argc,
		char** argv,
		AES_OPTIONS &aes_options)
{
	/* defaults */
	aes_options.blk_op_mode			= ECB;
	aes_options.encrypt				= true;
	aes_options.demo				= false;
	aes_options.buf_len				= 64* 1024* 1000;
	aes_options.file_in				= "";
	aes_options.file_out			= "";
	aes_options.processing_method	= CPU_HWNI;
	aes_options.num_iterations		= 3;
	aes_options.cpu_count			= 1;
	
	int argId;
	
	while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"in",		required_argument,		0,  'i'},
            {"out",		required_argument,		0,  'o'},
            {"buf",		required_argument,		0,  'b'},
            {"demo",	no_argument,			0,  'd'},
			{"cpu", 	required_argument,		0,  'c'},
			{"gpu", 	required_argument,    	0,  'g'},
			{"split", 	required_argument,		0,  's'},
			{"help", 		no_argument,    		0,  'h'},
			{"verbose", 	no_argument,			0,  'v'},
            {0,    			0,      				0, 	  0}
        };

       argId = getopt_long(argc, argv, "iob:cgs:hv",
                 long_options, &option_index);
        if (argId == -1)
            break;

        switch (argId) {
        case 'i':
    	   aes_options.file_in = optarg;
           break;
        case 'o':
           aes_options.file_out = optarg;
           break;
        case 'b':
    	   aes_options.buf_len = atoi(optarg)* 1024* 1000;
           break;
        case 'd':
        	aes_options.demo = true;
        	break;
        case 'c':
    	   	aes_options.processing_method = CPU_HWNI;
    	   	aes_options.cpu_count = atoi(optarg);
           break;
		case 'g':
		{
			string str(optarg);
    	   	istringstream ss(str);
			string token;
			while(std::getline(ss, token, ','))
				aes_options.cl_device_ids.push_back(atoi(token.c_str()));

			/* if no device specified, we use first device */
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
		   break;
		case 's':
    	{
			string str(optarg);
		   	istringstream ss(str);
			string token;
			while(std::getline(ss, token, ','))
				aes_options.cl_device_splits.push_back(atoi(token.c_str()));
			}
			break;
		   
		case 'h':
			cout << " --in [file] \t\t\t file input (plaintext) " << endl;
			cout << " --out [file] \t\t\t file output (ciphertext) " << endl;
			cout << " --buf [num] \t\t\t buffer size " << endl << endl;
			cout << " --cpu [num] \t\t\t process using CPU core count " << endl;
			cout << " --gpu [dev1,dev2] \t\t process using GPU devices "
					"[dev1,dev2] " << endl;
			cout << " --split  [sp1,sp2]\t\t split work for GPUs [sp1,sp2], "
					"CPU [T-sum(spx)] " << endl << endl;
			cout << " --help  \t\t\t display help " << endl;
			cout << " --vers  \t\t\t display version " << endl << endl;
			exit(0);
        	break;

		case 'v':
			cout << " ACCAES, Accelerate AES, RC1" << endl << endl;

			cout << " Application:\t\t ACCAES RC1, @2013-2014" << endl;
			cout << " Author:\t\t Lupescu Grigore, grigore.lupescu@gmail.com"
					<< endl;

			cout << " Algorithm:\t\t AES encryption only " << endl;
			cout << " Operation modes:\t ECB128, ECB256 " << endl;

			cout << " Programming:\t\t C/C++, OpenMP/AESNI, OpenCL " << endl;
			cout << " OS:\t\t\t Windows, Linux" << endl;
			cout << " HW:\t\t\t multicore CPU + multiple GPUs " << endl << endl;
			exit(0);
        	break;

       default:
           printf("?? getopt returned character code 0%o ??\n", argId);
        }
    }

	if(op_check_options(aes_options) == false)
		exit(1);

}


/*******************************************************
*	Function: io_IN
*	Info: prepare input
*******************************************************/
void io_IN(unsigned char* &buf_in,
		unsigned char* &buf_out,
		AES_OPTIONS& aes_opt)
{
	/* allocate buf_in memory and read/generate */
	if(aes_opt.file_in.size() != 0)
		io_read_file(buf_in, aes_opt.buf_len, aes_opt.file_in.c_str());

	/* allocate buf_out memory */
	buf_out = new uchar[aes_opt.buf_len];
	DIE(buf_out == NULL, "Could not allocate memory buf_out\n");
}


/*******************************************************
*	Function: io_OUT
*	Info: validate/write output
*******************************************************/

void io_OUT(unsigned char * &buf_in,
		unsigned char * &buf_out,
		AES_OPTIONS aes_opt)
{
	unsigned buf_len = aes_opt.buf_len;

	if(aes_opt.file_out.size() != 0)
		io_write_file(buf_out, buf_len, aes_opt.file_out.c_str());

	delete[] buf_in;
	delete[] buf_out;
}

/*******************************************************
*	Function: io_write_file
*	Info: write binary file
*******************************************************/
void io_write_file(unsigned char *buffer,
		unsigned size,
		const char* filename)
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
*	Function: io_read_file
*	Info: read binary file
*******************************************************/
void io_read_file(unsigned char*& buffer,
		unsigned &size,
		const char* filename)
{
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

	/* Actual file read */
	DIE(fread(buffer, sizeof(unsigned char), size, file) != size,
			"File read error !!!\n");

	/* Read file contents into buffer */
	fclose(file);
}

/*******************************************************
*	Function: io_display_hex
*	Info: display data as HEX from buffer
*******************************************************/
void io_display_hex(unsigned char* buffer,
		unsigned size)
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
*	Function: io_display_ascii
*	Info: display data as ASCII from buffer
*******************************************************/
void io_display_ascii(unsigned char* buffer,
		unsigned size)
{
	for (uint c=0; c<size; c++)
		printf("%c", buffer[c]);

	/* Add an extra line feed for good measure */
	printf("\n\n");
}
