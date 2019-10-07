find_package(OpenMP)

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

add_executable(main main.cpp FR.h experimentation.cpp experimentation.h FR.cpp fft.cpp fft.h)
target_include_directories(main PUBLIC ${CMAKE_SOURCE_DIR}/libfqfft)
target_include_directories(main PUBLIC ${CMAKE_SOURCE_DIR}/libff)
target_link_libraries(main libfqfft)
target_link_libraries(main ff)
target_link_libraries(main OpenMP::OpenMP_CXX)
target_link_libraries(main ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})