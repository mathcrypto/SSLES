//
//  merkle.hpp
//  src
//
//  Created by Amira Bouguera on 27/05/2019.
//  Copyright © 2019 Amira Bouguera. All rights reserved.

#ifndef MERKLE_HPP_
#define MERKLE_HPP_

//#include <../gadgets/libsnark/libsnark/common/data_structures/merkle_tree.hpp>
//#include <libsnark/gadgetlib1/gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

//#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
//#include <libsnark/gadgetlib2/variable.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>

//#include <libff/algebra/fields/field_utils.tcc>


#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>



typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT; 
    


char *merkleproof_prove( const char *pk_file, libff::bit_vector leaf, libff::bit_vector digest, libff::bit_vector Selector, libff::bit_vector root, const libsnark::pb_linear_combination<FieldT> successful);
    


int merkleproof_genkeys( const char *pk_file, const char *vk_file );


bool merkleproof_verify( const char *vk_json, const char *proof_json );

#ifdef __cplusplus
} // extern "C"
#endif

// MERKLE_HPP_
#endif
