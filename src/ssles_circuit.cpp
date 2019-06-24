//
//  main.cpp
//  src
//
//  Created by Amira Bouguera on 27/05/2019.
//  Copyright © 2019 Amira Bouguera. All rights reserved.
//


#include "merkle.hpp"
//#include "../depends/multiplexer_gadget.tcc" //Multiplexer gadget
#include <ethsnarks/src/jubjub/eddsa.hpp>
#include <ethsnarks-hashpreimage/circuit/hashpreimage.cpp>
//#include "../gadgets/ethsnarks/src/jubjub/eddsa.cpp"
//#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>



using namespace libsnark;

using namespace std;

//using namespace ethsnarks;
using ethsnarks::jubjub::PureEdDSA;  // signature gadget
using ssles::merkle_proof; // merkle proof gadget
using ethsnarks::mod_hashpreimage; // hash preimage gadget


namespace ssles {
    
    
    
    
   //const size_t sha256_digest_len = 256;
    

    
    template<typename FieldT>
    
    class ssles_circuit : public gadget<FieldT>
    {
        
        
    public:
        // Constructor
        
       
        
        
        const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        const pb_variable_array<FieldT> input_as_bits;  // unpacked R1CS input since these values
        libsnark::multipacking_gadget<FieldT> packer;
        libsnark::sha256_compression_function_gadget<FieldT> sha256;
        //snarks::ethsnarks::jubjub::PureEdDSA<FieldT> sign;
        std::shared_ptr<PureEdDSA<FieldT>> sig; //gadget
        std::shared_ptr<mod_hashpreimage<FieldT>> hash; //gadget
        std::shared_ptr<sha256_compression_function_gadget<FieldT>> root; //gadget
        std::shared_ptr<digest_variable<FieldT> > computed_hash;
        std::shared_ptr<digest_variable<FieldT> > computed_root;
        std::shared_ptr<digest_variable<FieldT> > signed_msg;
        pb_variable<FieldT> zero;
    
        
        ssles_circuit(
                     protoboard<FieldT> &in_pb,
                     //const size_t tree_depth,
                     const merkle_proof<FieldT> & rootDigest, // root hash of all participants' public keys
                     const digest_variable<FieldT> & hashDigest, // hash of the signed message
                     const digest_variable<FieldT> & random,// the random here is the message m
              // starting private inputs
                     const digest_variable<FieldT> & sig, // not sure if sig is digest
                     const digest_variable<FieldT> & msg,
                     const digest_variable<FieldT> & path,
                     const digest_variable<FieldT> & leafDigest,
                     const pb_linear_combination_array<FieldT> & directionSelector,//   Merkled path: mp the Merkle path mp leads from the public key pk to the root hash rh,
                     const digest_variable<FieldT> & pk, //The signer’s public key: pk.
                     const std::string &annotation_prefix
                     
                      
              

                     ) :
        gadget<FieldT>(in_pb, "ssles_gadget")
        
        
        
        
        {
           
            
            // Allocate space for the verifier input which will be the public inputs, in our case, they are two elements of size 256 each
            // will the random beacon have 256 bits?
            const size_t input_size_in_bits = sha256_digest_len * 3;
            
            {
                
                const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
                
                // we allocate space for the field elements to be of size input_size_in_field_elements
                input_as_field_elements.allocate(in_pb, input_size_in_field_elements, "input_as_field_elements");
                
                // finally our input size to size of field elements
                this->pb.set_input_sizes(input_size_in_field_elements);
            }
            
            
            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
            // SHA256's length padding, emplace_back will add 0 or 1 at the end
           
            
            
            input_as_bits.insert(input_as_bits.end(), rootDigest.bits.begin(), rootDigest.bits.end());
            input_as_bits.insert(input_as_bits.end(), hash.bits.begin(), hash.bits.end());
            input_as_bits.insert(input_as_bits.end(), random.bits.begin(), random.bits.end());
            
            assert(input_as_bits.size() == input_size_in_bits);
            
            
            // packer(in_pb, hasher.result().bits, public_inputs, FieldT::capacity(), FMT(annotation_prefix, ".packer"))
            // packer has to enforce bitness
            packer(in_pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " packer"));
            
          
            
            
            
            
            void generate_r1cs_constraints()
            {
                
                
                // Multipacking constraints (for input validation)
                packer.generate_r1cs_constraints(true);
                //rootDigest->generate_r1cs_constraints();
                // pathDigest->generate_r1cs_constraints();
                
                
                //ensure consistency of pathDigest and leafDigest with outputs left and right
                lhs->generate_r1cs_constraints();
                rhs->generate_r1cs_constraints();
                //block->generate_r1cs_constraints();
                // h_block->generate_r1cs_constraints();
                
                hash->generate_r1cs_constraints(false); /* ensure correct hash computations */
                
                // computed_root * 1 == rootDigest
                
                pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, root), "Enforce valid proof");
                
                
                
                
                //bit_vector_copy_gadget generate_r1cs_constraints(const bool enforce_source_bitness, const bool enforce_target_bitness); bits were enforced for computed_root and root
                //check_root->generate_r1cs_constraints(false, false);
                
                // Sanity check
                generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
                
                
            }
            void generate_r1cs_witness()
            {
                //this->pb.val(zero) = FieldT::zero();
                
                packer->generate_r1cs_witness_from_bits();
                lhs->generate_r1cs_witness();
                rhs->generate_r1cs_witness();
                //block->generate_r1cs_witness();
                
                /* compute hash */
                hash->generate_r1cs_witness();
                // check_root->generate_r1cs_witness();
                
                
                
                
                
                
                
                
            }
        };
        
        template<typename FieldT>
        
        // The statement (public values) is called primary input while the witness (the secret values) is called auxiliary input.
        
        const r1cs_primary_input<FieldT> l_input_map (const libff::bit_vector &root, const libff::bit_vector &digest)
        
        
        
        {
            
            return (libff::pack_bit_vector_into_field_element_vector<FieldT>(root),
                    libff::pack_bit_vector_into_field_element_vector<FieldT>(digest));
            
            
            
        }
           
            assert(root.bits.size() == sha256_digest_len);
            assert(digest.bits.size() == sha256_digest_len);
            
            
            
            {
                
                
                libff::bit_vector input_as_bits;
                input_as_bits.insert(input_as_bits.end(), root.begin(), root.end());
                input_as_bits.insert(input_as_bits.end(), digest.begin(), digest.end());
                
                
                std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;
                
                
                std::vector<FieldT> input_as_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
                
                
                std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;
                
                return input_as_field_elements;
            
            
            
            
            
            
            
    
}
 using namespace libsnark;
 using ssles::ssles_circuit;
 using libff::alt_bn128_pp;
 using ethsnarks::ppT;
 using ethsnarks::FieldT;
 using ethsnarks::ProtoboardT;
 //using ethsnarks::field2bits_strict.cpp;
 
 //Setup
 
 
 char *ssles_circuit_prove( const char *pk_file, libff::bit_victor leaf(0, 256), libff::bit_vector digest(0, 256), libff::bit_vector selector(0, 256), libff::bit_vector root(0, 256), const pb_linear_combination<FieldT> successful)
 {
 
 ppT::init_public_params();
 
 libff::alt_bn128_pp::init_public_params();
 
 
 ProtoboardT pb;
 ssles_circuit ssles(pb, "ssles");
 ssles.generate_r1cs_constraints();
 merkle_proof.generate_r1cs_constraints();
 mod_hashpreimage.generate_r1cs_constraints();
 
 
 if( ! pb.is_satisfied() )
 {
 return nullptr;
 }
 
 // the proof in a json file
 const auto json = ssles::snark_prove_from_pb(pb, pk_file);
 // auto json = proof_to_json (proof, primary_input);
 
 
 return std::strdup(json.c_str());
 }
 
 
 
 int ssles_circuit_genkeys( const char *pk_file, const char *vk_file )
 {
 // Generate the verifying/proving keys. (This is trusted setup!)
 libff::alt_bn128_pp::init_public_params();
 
 ProtoboardT pb;
 Gadget<FieldT> ssles(pb, "ssles");
 ssles.generate_r1cs_constraints();
 
 return ssles::snark_genkeys<ssles::ssles_circuit>(pk_file, vk_file);
 }
 
 
 bool ssles_circuit_verify( const char *vk_json, const char *proof_json )
 {
 return ssles::snark_verify( vk_json, proof_json );
 }
 
 
 
 };
 
 
 
 
 
 }
