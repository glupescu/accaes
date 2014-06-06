cmake_minimum_required(VERSION 2.6)
project(ACCSEC)

############################
# DEBUG/RELEASE
############################

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

############################
# COMPILE OPTIONS
############################

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	include_directories("/opt/AMDAPP/include")
	link_directories("/opt/AMDAPP/lib/x86_64/")
	SET (CMAKE_CXX_FLAGS "-O3 -Wall -maes -fopenmp")
ELSE("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	include_directories("C:\\Program\ Files\\Intel\\OpenCL\ SDK\\3.0\\include")
	link_directories("C:\\Program\ Files\\Intel\\OpenCL\ SDK\\3.0\\lib\\x86")
ENDIF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

file(COPY kernel.cl DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

SET (EXTRA_LIBS ${EXTRA_LIBS} aes_openssl)
SET (EXTRA_LIBS ${EXTRA_LIBS} aes_gpu)
SET (EXTRA_LIBS ${EXTRA_LIBS} aes_hwni)
SET (EXTRA_LIBS ${EXTRA_LIBS} aes_hybrid)
SET (EXTRA_LIBS ${EXTRA_LIBS} aes_base)
SET (EXTRA_LIBS ${EXTRA_LIBS} aes_profiler)
SET (EXTRA_LIBS ${EXTRA_LIBS} io)
SET (EXTRA_LIBS ${EXTRA_LIBS} OpenCL)
SET (EXTRA_LIBS ${EXTRA_LIBS} ssl)
SET (EXTRA_LIBS ${EXTRA_LIBS} crypto)
SET (EXTRA_LIBS ${EXTRA_LIBS} rt)

############################
# BUILD
############################

add_library(aes_openssl aes_openssl.cpp)
add_library(aes_gpu aes_gpu.cpp)
add_library(aes_hwni aes_hwni.cpp)
add_library(aes_hybrid aes_hybrid.cpp)
add_library(aes_base aes_base.cpp)
add_library(aes_profiler aes_profiler.cpp)
add_library(io io.cpp)
add_executable(accsec main.cpp)
target_link_libraries(accsec ${EXTRA_LIBS})
