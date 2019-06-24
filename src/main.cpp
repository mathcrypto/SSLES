//
// ssles_circuit.hpp
//  src
//


#ifndef SSLES_CIRCUIT_HPP_
#define SSLES_CIRCUIT_HPP_


#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>



#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>



    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT; 



//char *ssles_circuit_prove( const char *pk_file, libff::bit_vector leaf, libff::bit_vector digest, libff::bit_vector Selector, libff::bit_vector root, const libsnark::pb_linear_combination<FieldT> successful);



    int ssles_circuit_genkeys( const char *pk_file, const char *vk_file );


    bool ssles_circuit_verify( const char *vk_json, const char *proof_json );

#ifdef __cplusplus
} // extern "C"
#endif

// SSLES_CIRCUIT_HPP_
#endif







int main () {


    return 0;
}
