include_directories(.)

add_executable(
merkle_proof
merkle.hpp
)
target_link_libraries(
merkle_proof

snark
)
target_include_directories(
merkle_proof

PUBLIC
${DEPENDS_DIR}/libsnark
${DEPENDS_DIR}/libsnark/depends/libfqfft
${DEPENDS_DIR}/libsnark/depends/libff

)

add_executable(
preimage_proof
preimage_proof.hpp
)
target_link_libraries(
preimage_proof

snark
)
target_include_directories(
preimage_proof

PUBLIC
${DEPENDS_DIR}/libsnark
${DEPENDS_DIR}/libsnark/depends/libfqfft
${DEPENDS_DIR}/libsnark/depends/libff

)


