#include "main.h"


AES_PROFILER::AES_PROFILER(long buf_len){
	this->buf_len = buf_len;
}


#if defined(_MSC_VER)

void AES_PROFILER::start(){
	LARGE_INTEGER li;

	QueryPerformanceCounter(&li);
	starttime = li.QuadPart;
}

void AES_PROFILER::stop(){

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
	cout << "time " << time_diff << " ms, throughput "
		<< throughput << " MB/sec" << endl;
}


#else
#if defined(__GNUC__)

void AES_PROFILER::start(){
	/* record start time */
	clock_gettime(CLOCK_REALTIME, &starttime);
}

void AES_PROFILER::stop(){
	/* record end time & compute difference */
	clock_gettime(CLOCK_REALTIME, &endtime);

	time_diff = ((endtime.tv_sec * 1000000000) + endtime.tv_nsec)
			- ((starttime.tv_sec * 1000000000) + starttime.tv_nsec);
	time_diff = time_diff / 1000000;

	throughput = ((long double)buf_len/(1000*1024))*(1000/time_diff);

	/* display info */
	cout << "time " << time_diff << " ms, throughput "
			<< throughput << " MB/sec" << endl;
}

#endif
#endif