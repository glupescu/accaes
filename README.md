ACCAES - Accelerate AES

###############################
General info
###############################

- demo of AESNI multicore acceleration
- demo of GPGPU AESNI acceleration
- demo of CPU AESNI + GPGPU acceleration

###############################
General compilation
###############################

[1] Start a shell and type "cmake ."
[2] Compile using the generated Makefile/*.sln project
	[a] Makefile => make clean && make
	[b] *sln project => open with Visual Studio and compile

###############################
Prerequisites ACCSEC on Linux
###############################

The following are requred prior to compilation:
- OpenSSL libraries
- OpenCL 
- AESNI support in compiler
- G++ 4.8 or above (G++ 4.6/4.7 yield considerable weaker results in AESNI)

###############################
Prerequisites ACCSEC on Windows
###############################

Requires Windows Vista/7/8. Tested with Windows 8.1

[1] Install Visual Studio with cl compiler - tested Visual Studio 2013 Ultimate
[2] Install cmake, add to PATH
[3] Go to source directory. Open Visual Studio CMD, type "cmake ."
[4] Open the generated solution in Visual Studio 2013
[5] Install AMD APP SDK - for headers & OpenCL.lib dependancy
[6] Get OpenSSL from http://slproweb.com/products/Win32OpenSSL.html - tested with Win32 OpenSSL v1.0.1f
	[a] LINK \lib\VC\static\libeay32MT.lib AND \lib\VC\static\ssleay32MT.lib
[7] Include any additional headers from mentioned frameworks
[8] Build "RELEASE" version of AESBench


C:\Users\Lupescu\Desktop\srcWin\Release>AESBench.exe -h
Allowed options:
  -d [ --dec ]          do AES decryption, default encryption
  -i [ --in ] arg       input file
  -o [ --out ] arg      output file
  -b [ --buf ] arg      generate MB data for I/O
  -c [ --cpu ]          CPU AESNI multicore
  -g [ --gpu ] arg      GPU OpenCL, CL dev ids
  -s [ --split ] arg    OpenCL % split work, separate by comma
  -h [ --help ]         produce help message
  -v [ --vers ]         version number

C:\Users\Lupescu\Desktop\srcWin\Release>AESBench.exe -b 256 -c
PERFORMANCE time 218.685 ms, throughput 1170.64 MB/sec
