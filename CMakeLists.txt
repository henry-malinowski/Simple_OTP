cmake_minimum_required(VERSION 3.7)
project(Simple_OTP)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-march=haswell -fopenmp -msse4.1")
set(GCC_COVERAGE_FLAGS "-O0" "-Wall" "-g" "-fsanitize=leak" "-fstrict-overflow")

set(SOURCE_FILES main.c)
add_executable(Simple_OTP ${SOURCE_FILES})