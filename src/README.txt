
###############################
Porting ACCSEC to Windows
###############################

Requires Windows Vista/7/8. Tested with Windows 8.1

[1] Install Visual Studio with cl compiler - tested Visual Studio 2013 Ultimate
[2] Install cmake, add to PATH
[3] Go to source directory. Open Visual Studio CMD, type "cmake ."
[4] Open the generated solution in Visual Studio 2013
[5] Install AMD APP SDK - for headers & OpenCL.lib dependancy
[6] Get Boost from http://www.boost.org/users/download/ - tested with 1.53
	[a] Open Visual Studio CMD and run bootstrap.cmd
	[b] Run "./b2"
	[c] See lib in bin.v2\libs\program_options\build\msvc\release\link-static\threading-multi 
	[d] Adjust namig of lib if LINK problems occur (libboost_program_options-vc110-mt-1_53.lib)
[7] Get OpenSSL from http://slproweb.com/products/Win32OpenSSL.html - tested with Win32 OpenSSL v1.0.1f
	[a] LINK \lib\VC\static\libeay32MT.lib AND \lib\VC\static\ssleay32MT.lib
[8] Include any additional headers from mentioned frameworks
[9] Build "RELEASE" version of AESBench


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