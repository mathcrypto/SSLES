/*
* Verify that SHA256(private<secret>) == public<input>
*/


#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>



using namespace libsnark;
using namespace std;
using namespace libff;



typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
const size_t sha256_digest_len = 256;  
//const size_t SHA256_block_size = 512;

bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};
    



template<typename FieldT>


class preimage_proof_gadget : public gadget<FieldT>
    {

{
public:
   
     // Verifier inputs
        
    const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    const pb_variable_array<FieldT> input_as_bits;  // unpacked R1CS input since these values
    const size_t input_size_in_fields;
    shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker;
    typedef  shared_ptr<sha256_compression_function_gadget<FieldT>> sha256_gadget; //The sha256_compression_function_gadget only implements the SHA256 compression function. 
    shared_ptr<digest_variable<FieldT>> h_result;   
    shared_ptr<block_variable<FieldT>>  block;
    shared_ptr<digest_variable<FieldT>> preimage; 
    shared_ptr<digest_variable<FieldT>> computed_hash; 
    shared_ptr<sha256_compression_function_gadget<FieldT>> hash; 
    pb_variable<FieldT> zero; 


        
        


     preimage_proof_gadget( protoboard<FieldT>& pb,

        const digest_variable<FieldT> & h_result,
        const digest_variable<FieldT> & preimage,     
        const string &annotation_prefix                    
     
  
    ) : gadget<FieldT>(pb, "preimage_proof_gadget")

      {         const size_t input_size_in_bits = sha256_digest_len; 

            
            {
            	// number of field packed elements as input
                
                input_size_in_fields = libff::div_ceil(input_size_in_bits, FieldT::capacity()); 

                /* fast ceiling of an integer division 
            	   long long div_ceil(long long x, long long y)
                {
                    return (x + (y-1)) 
                }
                 static size_t capacity() { return num_bits - 1; } 
                  */
             
     
                // we allocate space for the field elements to be of size input_size_in_field_elements

                input_as_field_elements.allocate(pb, input_size_in_fields, "public_inputs");
                
               
                this->pb.set_input_sizes(input_size_in_field_elements); 

            }

        
       
        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
            

        input_as_bits.insert(input_as_bits.end(), h_result.bits.begin(), h_result.bits.end());
            
            
            
        unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpacker")));
            
            

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
            
    
            
            // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
                                          }
        
            
            
        // Inputs are 256 bit padding and 256 bit message block
        block.reset(new block_variable<FieldT>(in_pb, {
             preimage->bits,
             padding_var
             }, "block"));
             
        assert(block.bits.size() == SHA256_block_size);
            
            
        // Inputs are 256 bit IV and 512 bit h_block (64 bytes)
            
        computed_hash.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_hash")));
        hash.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                    IV,
                                                                    block->bits,
                                                                    *computed_hash,
                                                                    FMT(this->annotation_prefix, "computed_hash")));
            
            
        assert(computed_hash.size() == sha256_digest_len);
         
        assert(input_as_bits.size() == input_size_in_bits);
            
       
    
   }

    void generate_r1cs_constraints()
    {
       
        unpacker.generate_r1cs_constraints(true);
        // Sanity check
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
            
        hash->generate_r1cs_constraints(false); /* ensure correct hash computations */
            
        // Constraint that computed_hash * 1 == h_result which is equivalent to computed_hash == h_result
            
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_hash, h_result), "Enforce valid proof");
            
    }


    void generate_r1cs_witness(
        const libff::bit_vector& secret, const libff::bit_vector& pub_hash
    ) {
           
        // Fill our digests with our witnessed data
        preimage->bits.fill_with_bits(this->pb, secret);
        

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our gadgets
     
        
        hash->generate_r1cs_witness();
        unpacker->generate_r1cs_witness_from_bits();
            
            
        pub_hash->bits.fill_with_bits(this->pb, h_result);
       
            
            
            
            
        }
    };
 
    
    template<typename FieldT>
    
    // The statement (public values) is called primary input while the witness (the secret values) is called auxiliary input.
    
    const r1cs_primary_input<FieldT> primary_inputs (const bit_vector &pub_hash)
    
    
    
    {
        
        assert(pub_hash.bits.size() == sha256_digest_len);
    
        bit_vector input_as_bits;

        input_as_bits.insert(input_as_bits.end(), pub_hash.begin(), pub_hash.end());
  
        
        
        std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;
        
        
        std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
        
        
        std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;
        
        return input_as_field_elements;



    }
       
