cmake_minimum_required(VERSION 3.15)
project(anonstake)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cmake-build-debug)
SET(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/cmake-build-debug)

add_subdirectory(libfqfft)
add_library(libfqfft INTERFACE IMPORTED)

add_subdirectory(main)
