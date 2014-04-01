CC=g++
LDFLAGS=-lOpenCL -lboost_program_options -fopenmp
CFLAGS=-I/usr/local/cuda/include -I/usr/include/boost -I/usr/include/ -maes

all:	accsec

accsec: aes_bench.o aes_gpu.o aes_hwni.o aes_hybrid.o aes_openssl.o aes_profiler.o aes_simple.o main.o io.o
	$(CC) $(LDFLAGS) aes_bench.o aes_gpu.o aes_hwni.o aes_hybrid.o aes_openssl.o aes_profiler.o aes_simple.o main.o io.o -o accsec

io.o: io.cpp
	$(CC) $(CFLAGS) -c io.cpp
	
main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp
	
aes_bench.o: aes_bench.cpp
	$(CC) $(CFLAGS) -c aes_bench.cpp

aes_gpu.o: aes_gpu.cpp
	$(CC) $(CFLAGS) -c aes_gpu.cpp

aes_hwni.o: aes_hwni.cpp
	$(CC) $(CFLAGS) -c aes_hwni.cpp
	
aes_hybrid.o: aes_hybrid.cpp
	$(CC) $(CFLAGS) -c aes_hybrid.cpp
	
aes_openssl.o: aes_openssl.cpp
	$(CC) $(CFLAGS) -c aes_openssl.cpp

aes_profiler.o: aes_profiler.cpp
	$(CC) $(CFLAGS) -c aes_profiler.cpp

aes_simple.o: aes_simple.cpp
	$(CC) $(CFLAGS) -c aes_simple.cpp
	
clean:
	rm -f accsec *.o
	
