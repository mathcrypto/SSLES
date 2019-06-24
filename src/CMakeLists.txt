include_directories(.)

add_executable(
main

main.cpp
)
target_link_libraries(
main 

 ethsnarks_common SHA3IUF ethsnarks_gadgets ethsnarks_verify
ff ethsnarks_jubjub ethsnarks_pinocchio ff
ethsnarks_common
ethsnarks_verify
SHA3IUF
ethsnarks_gadgets

ethsnarks_jubjub


ethsnarks_pinocchio
)
target_include_directories(
main

PUBLIC
${DEPENDS_DIR}/ethsnarks
${DEPENDS_DIR}/ethsnarks/depends/SHA3IUF
${DEPENDS_DIR}/ethsnarks/depends/libsnark
${DEPENDS_DIR}/ethsnarks/depends/libsnark/depends/libff
${DEPENDS_DIR}/ethsnarks/depends/libsnark/depends/libfqfft

)




