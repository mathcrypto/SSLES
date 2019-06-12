include_directories(.)

add_executable(
merkle
merkle.hpp
)
target_link_libraries(
merkle

snark
)
target_include_directories(
merkle

PUBLIC
${DEPENDS_DIR}/libsnark
${DEPENDS_DIR}/libsnark/depends/libfqfft
${DEPENDS_DIR}/libsnark/depends/libff

)


add_executable(
test
test.cpp
)
target_link_libraries(
test

snark
)
target_include_directories(
test

PUBLIC
${DEPENDS_DIR}/libsnark
${DEPENDS_DIR}/libsnark/depends/libfqfft
${DEPENDS_DIR}/libsnark/depends/libff

)

