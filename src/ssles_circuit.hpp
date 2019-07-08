#ifndef SSLES_CIRCUIT_HPP_
#define SSLES_CIRCUIT_HPP_

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>



#ifdef __cplusplus
extern "C" {
#endif




	typedef libff::alt_bn128_pp ppT;
	typedef libff::Fr<ppT> FieldT; 
	
const extern size_t SSLES_TREE_DEPTH;

/**
* Prover inputs is a JSON dictionary with the following structure:
* {
*    "root": "0x..",     // Merkle root
*    "exthash": "0x...", // Hash of external arguments 
*    "secret": "0x...",  // Secret for the leaf
*    "address": 1234,    // Index of the leaf, or address of the leaf in the tree
*    "path": ["0x...", "0x...", ...] // Merkle tree authentication path
* }
*
* Returns proof as JSON string
*/
char *ssles_prove_json( const char *pk_file, const char *in_json );


char *ssles_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_exthash,
    const char *in_secret,
    const char *in_address,
    const char **in_path
);

int ssles_genkeys( const char *pk_file, const char *vk_file );

bool ssles_verify( const char *vk_json, const char *proof_json );

char* ssles_nullifier( const char *in_secret, const char *in_leaf_index );

size_t ssles_tree_depth( void );

#ifdef __cplusplus
} // extern "C" {
#endif

#endif