find_package(OpenMP)

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

add_library(fftlib main.cpp)
target_include_directories(fftlib PUBLIC ${CMAKE_SOURCE_DIR}/libfqfft)
target_include_directories(fftlib PUBLIC ${CMAKE_SOURCE_DIR}/libff)
target_link_libraries(fftlib libfqfft)
target_link_libraries(fftlib ff)
target_link_libraries(fftlib OpenMP::OpenMP_CXX)
target_link_libraries(fftlib ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
