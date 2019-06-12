
//#include <libsnark/gadgetlib1/protoboard.hpp>

//#include <libff/common/utils.hpp>

//#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> // from which we get the multipacking gadget
//#include <libsnark/gadgetlib2/variable.hpp>
//#include <libsnark/gadgetlib1/gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

//#include <libff/algebra/fields/field_utils.hpp>
//#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
//#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>


#include "merkle.hpp"
#include "../depends/multiplexer_gadget.hpp" //Multiplexer gadget
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

 using namespace libsnark;
 using namespace std;
 using namespace libff;


namespace ssles {
    
    
    
    const size_t sha256_digest_len = 256;
    const size_t SHA256_block_size = 512;
    
    
    
    bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};
    
    
    template<typename FieldT>
    
    class merkle_proof : public gadget<FieldT>
    {
        
        
    public:
        // Constructor
        
        
        
        
        const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        const pb_variable_array<FieldT> input_as_bits;  // unpacked R1CS input since these values
        const digest_variable<FieldT> currentDigest;
        const digest_variable<FieldT> left;
        const digest_variable<FieldT> right;
        const block_variable<FieldT>  block;
        libsnark::multipacking_gadget<FieldT> packer;
        libsnark::sha256_compression_function_gadget<FieldT> sha256;
        std::shared_ptr<multiplexer_gadget<FieldT>> lhs;
        std::shared_ptr<multiplexer_gadget<FieldT>> rhs;
        std::shared_ptr<sha256_compression_function_gadget<FieldT>> hash;
        std::shared_ptr<digest_variable<FieldT> > computed_root;
        const digest_variable<FieldT> rootDigest;
        const digest_variable<FieldT> pathDigest;
        const digest_variable<FieldT> leafDigest;
        const digest_variable<FieldT> directionSelector;
        pb_variable<FieldT> zero;
        pb_variable_array<FieldT> padding_var;
        
        merkle_proof(
                     protoboard<FieldT> & pb,
                     //const size_t tree_depth,
                     const digest_variable<FieldT> & rootDigest,
                     const digest_variable<FieldT> & pathDigest,
                     const digest_variable<FieldT> & leafDigest,
                     const pb_linear_combination_array<FieldT> & directionSelector,
                     const std::string &annotation_prefix
                     
                     
                     
                     
                     ) :
        gadget<FieldT>(pb, "merkle_proof_gadget")
        {
            
            
            
            // Allocate space for the verifier input which will be the public inputs, in our case, they are two elements of size 256 each
            
            const size_t input_size_in_bits = sha256_digest_len * 2;
            
            {
                
                const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
                
                //std::cout << "**************** input_size_in_field_elements: " << input_size_in_field_elements << "\n";
                //std::cout << "**************** FieldT::capacity(): " << FieldT::capacity() << "\n";
                // we allocate space for the field elements to be of size input_size_in_field_elements
                input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
                
                // finally our input size to size of field elements
                this->pb.set_input_sizes(input_size_in_field_elements);
            }
            
            
            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
            // SHA256's length padding, emplace_back will add 0 or 1 at the end
            for (size_t i = 0; i < 256; i++) {
                if (sha256_padding[i])
                    padding_var.emplace_back(ONE);
                else
                    padding_var.emplace_back(zero);
            }
            
            
            input_as_bits.insert(input_as_bits.end(), rootDigest.bits.begin(), rootDigest.bits.end());
            input_as_bits.insert(input_as_bits.end(), pathDigest.bits.begin(), pathDigest.bits.end());
            
            
            assert(input_as_bits.size() == input_size_in_bits);
            
            
            // packer(in_pb, hasher.result().bits, public_inputs, FieldT::capacity(), FMT(annotation_prefix, ".packer"))
            packer(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " packer"));
            
            
            
            const size_t currentDirection = 0;
            
            
            currentDirection = directionSelector[0];
            
            pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
            
            left.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, "left")));
            right.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, "right")));
            
            lhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *left, currentDirection, leafDigest, pathDigest, ".lhs"));
            rhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *right, currentDirection, pathDigest, leafDigest, ".rhs"));
            
            // assert(left.bits.size() == sha256_digest_len);
            //assert(right.bits.size() == sha256_digest_len);
            assert(lhs.result().bits.size() == sha256_digest_len);
            assert(rhs.result().bits.size() == sha256_digest_len);
            
            block.reset(new digest_variable<FieldT>(pb, SHA256_block_size, FMT(this->annotation_prefix, "block")));
            
            
            
            
            
            /* concatenate block = left || right */
            block.insert(block.end(), left.bits.begin(), left->bits.end());
            block.insert(block.end(), right.bits.begin(), right->bits.end());
            //block_variable<FieldT> inp(pb, path.left_digests[i], path.right_digests[i], FMT(this->annotation_prefix, " inp_%zu", i));
            
            
            // Inputs are 256 bit padding and 256 bit message block
            /* h_block.reset(new block_variable<FieldT>(in_pb, {
             block->bits,
             padding_var
             }, "hash_block"));
             */
            assert(block.bits.size() == SHA256_block_size);
            
            
            // Inputs are 256 bit IV and 512 bit h_block (64 bytes)
            // computed_root
            computed_root.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_root")));
            hash.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                      IV,
                                                                      block->bits,
                                                                      *computed_root,
                                                                      FMT(this->annotation_prefix, "computed_root")));
            
            
            assert(computed_root.size() == sha256_digest_len);
            
            
            
            
            
        }
        
        void generate_r1cs_constraints()
        {
            
            
            // Multipacking constraints (for input validation)
            packer.generate_r1cs_constraints(true);
            
            
            
            //ensure consistency of pathDigest and leafDigest with outputs left and right
            lhs->generate_r1cs_constraints();
            rhs->generate_r1cs_constraints();
            
            hash->generate_r1cs_constraints(false); /* ensure correct hash computations */
            
            // computed_root * 1 == rootDigest
            
             //this-pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, root), "Enforce valid proof");
            
            
            
            
            // Sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
            
            
        }
        void generate_r1cs_witness(const bit_vector &root,
                                   const bit_vector &digest0,
                                   const bit_vector &leaf,
                                   const bit_vector &selector
                                   )
        {
            //this->pb.val(zero) = FieldT::zero();
            
            leafDigest->bits.fill_with_bits(this->pb, leaf);
            directionSelector->bits.fill_with_bits(this->pb, selector);
            //pathDigest->bits.fill_with_bits(this->pb, digest0);
            
            
            packer->generate_r1cs_witness_from_bits();
            lhs->generate_r1cs_witness();
            rhs->generate_r1cs_witness();
            /* compute hash */
            hash->generate_r1cs_witness();
            
            
            
            
            
            
            
            
        }
    };
}  
    
    //template<typename FieldT>
    
    // The statement (public values) is called primary input while the witness (the secret values) is called auxiliary input.
    
    const r1cs_primary_input<FieldT> l_input_map (const bit_vector &root, const bit_vector &digest)
    
    
    
    {
        
        
        
    
     assert(root.bits.size() == sha256_digest_len);
     assert(digest.bits.size() == sha256_digest_len);
    
    
    
    
        
        
        bit_vector input_as_bits;
        input_as_bits.insert(input_as_bits.end(), root.begin(), root.end());
        input_as_bits.insert(input_as_bits.end(), digest.begin(), digest.end());
        
        
        std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;
        
        
        std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
        
        
        std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;
        
        return input_as_field_elements;
        }
        
        
        
    
    
