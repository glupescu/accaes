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

AES_PROFILER::AES_PROFILER(long buf_len){
	this->buf_len = buf_len;
}


#if defined(_MSC_VER)

/*******************************************************
*	Function: start
*	Info: start timer, set buffer len to encrypt
*******************************************************/
void AES_PROFILER::start(){
	LARGE_INTEGER li;

	QueryPerformanceCounter(&li);
	starttime = li.QuadPart;
}

/*******************************************************
*	Function: stop
*	Info: stop timer and display msg + time + MB/sec
*******************************************************/
void AES_PROFILER::stop(const char* msg){

	LARGE_INTEGER li;

	QueryPerformanceCounter(&li);
	endtime = li.QuadPart;
	time_diff = endtime - starttime;

	if (!QueryPerformanceFrequency(&li))
		cout << "QueryPerformanceFrequency failed!\n";

	long double cpu_freq = double(li.QuadPart) / 1000.0;
	time_diff = time_diff / cpu_freq;
	throughput = ((long double)buf_len / (1000 * 1024))*(1000 / time_diff);

	/* display info */
	cout << msg << "time " << time_diff << " ms, throughput "
		<< throughput << " MB/sec" << endl;
}


#else
#if defined(__GNUC__)

/*******************************************************
*	Function: start
*	Info: start timer, set buffer len to encrypt
*******************************************************/
void AES_PROFILER::start(){
	/* record start time */
	clock_gettime(CLOCK_REALTIME, &starttime);
}

/*******************************************************
*	Function: stop
*	Info: stop timer and display msg + time + MB/sec
*******************************************************/
void AES_PROFILER::stop(const char* msg){
	/* record end time & compute difference */
	clock_gettime(CLOCK_REALTIME, &endtime);

	time_diff = ((endtime.tv_sec * 1000000000) + endtime.tv_nsec)
			- ((starttime.tv_sec * 1000000000) + starttime.tv_nsec);
	time_diff = time_diff / 1000000;

	throughput = ((long double)buf_len/(1000*1024))*(1000/time_diff);

	/* display info */
	cout << msg << "time " << time_diff << " ms, throughput "
			<< throughput << " MB/sec" << endl;
}

#endif
#endif
