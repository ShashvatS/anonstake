cmake_minimum_required(VERSION 3.10)
project(anonstake)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(libfqfft)
add_library(libfqfft INTERFACE IMPORTED)

add_subdirectory(experiments)
add_subdirectory(libfft)
