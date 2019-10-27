find_package(OpenMP)

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

add_library(fft main.cpp)
target_include_directories(fft PUBLIC ${CMAKE_SOURCE_DIR}/libfqfft)
target_include_directories(fft PUBLIC ${CMAKE_SOURCE_DIR}/libff)
target_link_libraries(fft libfqfft)
target_link_libraries(fft ff)
target_link_libraries(fft OpenMP::OpenMP_CXX)
target_link_libraries(fft ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
