
/**
* Verify that SHA256(private<secret>) == public<input>
*/


#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> // for multipacking gadget
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp> 
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp> 




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


    public:

    // Verifier inputs

    const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    const pb_variable_array<FieldT> input_as_bits;  // unpacked R1CS input since these values
    const size_t input_size_in_fields;
    shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker;
    shared_ptr<sha256_compression_function_gadget<FieldT>> sha256_gadget; /* hashing gadget */
    shared_ptr<digest_variable<FieldT>> Hash;  
    shared_ptr<block_variable<FieldT>>  block; /* 512 bit block that contains preimage + padding */
    shared_ptr<digest_variable<FieldT>> preimage;  
    shared_ptr<digest_variable<FieldT>> computed_hash; 
    pb_variable_array<FieldT> padding_var; 
    pb_variable<FieldT> zero;  






    preimage_proof_gadget( protoboard<FieldT>& pb,

        const digest_variable<FieldT> & Hash,
        const digest_variable<FieldT> & preimage,     
        const string &annotation_prefix                    






        ) : gadget<FieldT>(pb, "preimage_proof_gadget")

             // Allocate space for the verifier input
    {         const size_t input_size_in_bits = sha256_digest_len; // probably should check if digest size is 256


        {
            
            // number of field packed elements as public inputs

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


            this->pb.set_input_sizes(input_size_in_fields); 

        }

        

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        // Verifier (and prover) inputs:
        Hash.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "Hash"));
        input_as_bits.insert(input_as_bits.end(), Hash.bits.begin(), Hash.bits.end());

        assert(input_as_bits.size() == input_size_in_bits);
        // multipacking_gadget(protoboard<FieldT> &pb, const pb_linear_combination_array<FieldT> &bits, const pb_linear_combination_array<FieldT> &packed_vars, const size_t chunk_size, const std::string &annotation_prefix="");
        unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpacker")));
        
        // Prover inputs:
        preimage.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "preimage"));


        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        
        
        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }
        


        // Initialize the block gadget for preimage's hash
        block.reset(new block_variable<FieldT>(pb, {
           preimage->bits,
           padding_var
       }, "block"));
        // check what assert function does
        assert(block.bits.size() == SHA256_block_size);


        

        computed_hash.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_hash")));
        
        // Initialize the hash gadget for preimage's hash
        sha256_gadget.reset(new sha256_compression_function_gadget<FieldT>(pb,
            IV,
            block->bits,
            *computed_hash,
            FMT(this->annotation_prefix, "computed_hash")));




    }


    void generate_r1cs_constraints()
    {
        // Multipacking constraints (for input validation) with enforcing bitness
        unpacker.generate_r1cs_constraints(true);
        preimage->generate_r1cs_constraints();
        // Sanity check, what is this sanity check and why do we need it?
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
        
        // Constraints to ensure the hash validates.
        sha256_gadget->generate_r1cs_constraints(false); 


        // ensure correct hash computations 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_hash, Hash), "Enforce valid proof");
     // Constraint that computed_root * 1 == rootDigest which is equivalent to computed_root == rootDigest
    }


    void generate_r1cs_witness(
        const bit_vector & secret, const bit_vector & pub_hash
        ) {

        // Fill our digests with our witnessed data
        preimage->bits.fill_with_bits(this->pb, secret);


        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our gadgets
        sha256_gadget->generate_r1cs_witness();
        unpacker->generate_r1cs_witness_from_bits(); 
        //unpacker->generate_r1cs_witness_from_packed();
        


        Hash->bits.fill_with_bits(this->pb, pub_hash); 





    }
};


template<typename FieldT>

// The statement (public values) is called primary input while the witness (the secret values) is called auxiliary input.

const r1cs_primary_input<FieldT> primary_inputs (const bit_vector &pub_hash)



{
   // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(pub_hash.size() == sha256_digest_len);

    std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), pub_hash.begin(), pub_hash.end());



    /* std::vector<FieldT> pack_bit_vector_into_field_element_vector(const bit_vector &v, const size_t chunk_bits) */
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    


    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;



}

