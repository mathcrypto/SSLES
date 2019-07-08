//Merkle tree proof of depth 1
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include "multiplexer_gadget.hpp" //Multiplexer gadget
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>




using namespace libsnark;
using namespace std;
using namespace libff;
using namespace ssles;


/*
       For Merkle tree authentication paths, path[0] corresponds to one layer below
       the root (and path[tree_depth-1] corresponds to the layer containing the leaf), while address_bits has the reverse order:
       address_bits[0] is LSB, and corresponds to layer containing the leaf, and address_bits[tree_depth-1] is MSB, and corresponds to
       the subtree directly under the root.
    */



typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libsnark::pb_variable<FieldT> VariableT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;
typedef libsnark::pb_linear_combination<FieldT> LinearCombinationT;
typedef libsnark::pb_linear_combination_array<FieldT> LinearCombinationArrayT;
typedef libsnark::gadget<ethsnarks::FieldT> GadgetT;
typedef libsnark::r1cs_constraint<FieldT> ConstraintT;

const size_t sha256_digest_len = 256;
//const size_t SHA256_block_size = 512;
 

    /*bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};
    */

template<typename FieldT>

class merkle_proof : public gadget<FieldT>
{


public:
        // Constructor



        const VariableT input_as_field_elements; /* R1CS input */
        const VariableT input_as_bits;  // unpacked R1CS input 
        typedef shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker; 
        typedef shared_ptr<sha256_two_to_one_hash_gadget<FieldT>> sha256_gadget; 
        const size_t tree_depth;
        const VariableArrayT pathDigest;
        const VariableT leafDigest;
        const VariableT rootDigest;
        const VariableT computed_root; 
        std::vector<ssles::multiplexer_gadget> multiplexer;
        shared_ptr<pb_linear_combination_array<FieldT>> directionSelector;
        std::vector<sha256_two_to_one_hash_gadget<FieldT>> hashers; //sha256 gadgets
        std::vector<block_variable<FieldT> > hash_inputs; /* 512 bit block that contains preimage + padding */
        pb_variable_array<FieldT> padding_var;
        pb_variable<FieldT> zero; 
        // const VariableArrayT m_address_bits;
        
       
       
      
       
        // std::vector<merkle_path_selector> m_selectors;
        
        //std::vector<ssles::multiplexer_gadget<FieldT>> lhs; //gadget
        //shared_ptr<ssles::multiplexer_gadget<FieldT>> rhs; //gadget
       
      
        //shared_ptr<digest_variable<FieldT>> left;
        //shared_ptr<digest_variable<FieldT>> right;
        
      
       
       
        
        merkle_proof(
         protoboard<FieldT> & pb,
         const size_t tree_depth,
         const VariableT & rootDigest,
         //const VariableT in_expected_root,
         const VariableArrayT & pathDigest,
         //const VariableArrayT in_path,
         const VariableT & leafDigest,
         //const VariableT in_leaf,
         const pb_linear_combination_array<FieldT> & directionSelector,
         //const VariableArrayT in_IVs
         //const VariableArrayT in_address_bits,
         const string &annotation_prefix




         ) :
        gadget<FieldT>(pb, "merkle_proof_gadget")
        {

           assert( in_depth > 0 );
           assert( in_address_bits.size() == in_depth ); //makes sense
           assert( in_IVs.size() >= in_depth ); // what is this?


        /*    // Allocate space for the verifier input which will be the public inputs, in our case, they are two elements of size 256 each

          const size_t input_size_in_bits = sha256_digest_len * 2;
          
          {

            const size_t input_size_in_field_elements = libff::div_ceil(input_size_in_bits, FieldT::capacity());
            
                // we allocate space for the field elements to be of size input_size_in_field_elements
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
            
                // finally our input size to size of field elements
            this->pb.set_input_sizes(input_size_in_field_elements);
          }
          
          

          zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

          input_as_bits.insert(input_as_bits.end(), rootDigest.bits.begin(), rootDigest.bits.end());
          input_as_bits.insert(input_as_bits.end(), pathDigest.bits.begin(), pathDigest.bits.end());
          
          
          assert(input_as_bits.size() == input_size_in_bits);
          


          
          unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpacker")));
          
         */

         for( size_t i = 0; i < tree_depth; i++ )
        {
            if( i == 0 )
            {  //multiplexer gadget
                multiplexer<FieldT>(
                    pb, sha256_digest_len, *output[i], in_address_bits[i], leafDigest, pathDigest[i], ".selector[%zu]", i);

               // lhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *left, currentDirection, leafDigest, pathDigest, ".lhs"));
               // rhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *right, currentDirection, pathDigest, leafDigest, ".rhs"));
          
            }
            else {
                m_selectors.push_back(
                    merkle_path_selector(
                        in_pb, m_hashers[i-1].result(), in_path[i], in_address_bits[i], // instead of leaf we take the result of previous hash
                        FMT(this->annotation_prefix, ".selector[%zu]", i)));
            }

            auto t = HashT( // this computes the hash with left and right digests and IV
                    in_pb, in_IVs[i],
                    {m_selectors[i].left(), m_selectors[i].right()},
                    FMT(this->annotation_prefix, ".hasher[%zu]", i));
           /* hash.reset(new sha256_compression_function_gadget<FieldT>(pb,
            IV, // IV of i
            block->bits, // block of i of left and right digests
            *computed_root,
            FMT(this->annotation_prefix, "computed_root")));
          */
            m_hashers.push_back(t); // what is push_back?
        }
    }

     for (size_t i = 0; i < tree_depth; ++i)
    {
        
        //  The propagators take a computed hash value (or leaf in the
         // base case) and propagate it one layer up, either in the left
         // or the right slot of authentication_path_variable.
        
        propagators.emplace_back(digest_selector_gadget<FieldT>(pb, digest_size, i < tree_depth - 1 ? internal_output[i] : leaf,
                                                                address_bits[tree_depth-1-i], path.left_digests[i], path.right_digests[i],
                                                                FMT(this->annotation_prefix, " digest_selector_%zu", i)));
    }

    check_root.reset(new bit_vector_copy_gadget<FieldT>(pb, computed_root->bits, root.bits, read_successful, FieldT::capacity(), FMT(annotation_prefix, " check_root")));
} */
 const VariableT result() const
    {
        assert( m_hashers.size() > 0 );

        return m_hashers.back().result();
    }
// hashers take the result and use it in the next gadget
          
        






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
          
          block.reset(new block_variable<FieldT>(pb, SHA256_block_size, FMT(this->annotation_prefix, "block")));
          
          
          
          
          
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
          unpacker.generate_r1cs_constraints(true);

          
          lhs->generate_r1cs_constraints();
          rhs->generate_r1cs_constraints();
              // Sanity check
          generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
          
            hash->generate_r1cs_constraints(false); /* ensure correct hash computations */
          
            // Constraint that computed_root * 1 == rootDigest which is equivalent to computed_root == rootDigest
          
          this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, rootDigest), "Enforce valid proof");
          
          // Ensure root matches calculated path hash
        this->pb.add_r1cs_constraint(
            ConstraintT(this->result(), 1, m_expected_root),
            FMT(this->annotation_prefix, ".expected_root authenticator"));
          
          
        }
        void generate_r1cs_witness(const bit_vector &root,
         const bit_vector &digest0,
         const bit_vector &leaf,
         const bit_vector &selector
         )
        {

            // Fill our digests with our witnessed data
          leafDigest->bits.fill_with_bits(this->pb, leaf);
          directionSelector->bits.fill_with_bits(this->pb, selector);
            //pathDigest->bits.fill_with_bits(this->pb, digest0);

            // Set the zero pb_variable to zero
          this->pb.val(zero) = FieldT::zero();




            // Generate witnesses as necessary in our gadgets

          lhs->generate_r1cs_witness();
          rhs->generate_r1cs_witness();

          hash->generate_r1cs_witness();
          unpacker->generate_r1cs_witness_from_bits();
          
          
          rootDigest->bits.fill_with_bits(this->pb, root);
          pathDigest->bits.fill_with_bits(this->pb, digest0);
          
          
          
          
          
        }
      };

      
    template<typename FieldT>
      
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

    