

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include<libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include<libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
//#include "../depends/multiplexer_gadget.hpp" //Multiplexer gadget



 using namespace libsnark;
 using namespace std;
 using namespace libff;
 //using namespace ssles;

 
  typedef libff::alt_bn128_pp ppT;
  typedef libff::Fr<ppT> FieldT;
  const size_t sha256_digest_len = 256;  
  
    
    template<typename FieldT>
    
    class merkle_proof_gadget : public gadget<FieldT>
    {
     
    private:

  // A private member variable or function cannot be accessed, or even viewed from outside the class. 
  // Only the class and friend functions can access private members.

    typedef  shared_ptr<sha256_two_to_one_hash_gadget<FieldT>> sha256_gadget;
    // Verifier inputs
    
    const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    const pb_variable_array<FieldT> input_as_bits;   // unpacked R1CS input since these values
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;  


    std::vector<block_variable<FieldT> > sha256_inputs; // the preimages of these hashes
    std::vector<digest_selector_gadget<FieldT> > digest_selector; // the digest selector gadget
    std::vector<digest_variable<FieldT> > internal_output; // the output hash inside the tree
    std::vector<sha256_gadget> hashers;

    std::shared_ptr<digest_variable<FieldT> > computed_root;
    std::shared_ptr<bit_vector_copy_gadget<FieldT> > check_root; 
    pb_variable_array<FieldT> tree_positions; // what's the difference between positions and path_vars?
    std::shared_ptr<merkle_authentication_path_variable<FieldT, sha256_gadget>> authvars; //gadget
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, sha256_gadget>> merkle_auth;
    pb_variable<FieldT> zero; 


     public:    // Constructor

      //A public member is accessible from anywhere outside the class but within a program. 
      //You can set and get the value of public variables without any member.
       
    const size_t tree_depth;
    //const size_t digest_size; 
    std::shared_ptr<digest_variable<FieldT>> rootDigest;
    shared_ptr<digest_variable<FieldT>> pathDigest0;
    shared_ptr<digest_variable<FieldT>> leafDigest;
    pb_linear_combination_array<FieldT> address_bits; // what are these address bits? 
    pb_linear_combination<FieldT> read_successful;
   
    shared_ptr<pb_linear_combination_array<FieldT>> directionSelector; // why this gadget is public and digestSelector is private?
    


    std::vector<digest_variable<FieldT> > left_digests; // this way we can have a vector of values and not only one
    std::vector<digest_variable<FieldT> > right_digests;

   
       merkle_proof_gadget( protoboard<FieldT>& pb,

        const size_t tree_depth,
        const digest_variable<FieldT> & rootDigest,
        const digest_variable<FieldT> & pathDigest0,
        const digest_variable<FieldT> & leafDigest,
        pb_variable_array<FieldT> & tree_positions, // pathDigests
     
        const pb_linear_combination_array<FieldT> &address_bits,
        const pb_linear_combination<FieldT> &read_successful,
        pb_variable<FieldT> & enforce,
        const pb_linear_combination_array<FieldT> & direction_Selector, // const pb_linear_combination<FieldT> &read_successful, // why do we copy gadgets? 
        //const pb_linear_combination_array<FieldT> & directionSelector,              

        const string &annotation_prefix                           
        
       // const pb_linear_combination_array<FieldT> &address_bits, // lsb and msb is it directionSelector?
        //const merkle_authentication_path_variable<FieldT, HashT> &path, // why there is HashT? should check merkle_authenticationpath gadget
        
     
  
    ) : gadget<FieldT>(pb, "merkle_proof_gadget")

       {
         
         const size_t input_size_in_bits = sha256_digest_len * 2; // which are root and digest0e
            
            {
                
                const size_t input_size_in_field_elements = libff::div_ceil(input_size_in_bits, FieldT::capacity());
                
                // we allocate space for the field elements to be of size input_size_in_field_elements
                input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
                
                // finally our input size to size of field elements
                this->pb.set_input_sizes(input_size_in_field_elements);
            }
            
            
          
            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

            input_as_bits.insert(input_as_bits.end(), rootDigest.bits.begin(), rootDigest.bits.end());
            input_as_bits.insert(input_as_bits.end(), pathDigest0.bits.begin(), pathDigest0.bits.end());
            
            
            assert(input_as_bits.size() == input_size_in_bits);
            
    
           
            
            unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpacker")));
            
            tree_positions.allocate(pb, tree_depth);
          authvars.reset(new merkle_authentication_path_variable<FieldT, sha256_gadget>(
            pb, tree_depth, "auth"
        ));
      
        
            
        merkle_auth.reset(new merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            tree_depth, //const size_t tree_depth,
            tree_positions, //   const pb_linear_combination_array<FieldT> &address_bits,
            leafDigest, //const digest_variable<FieldT> &leaf_digest,
            rootDigest, //const digest_variable<FieldT> &root_digest,
            *authvars,//   const merkle_authentication_path_variable<FieldT, HashT> &path,
            enforce, //  const pb_linear_combination<FieldT> &read_successful,
            ""     //  const std::string &annotation_prefix);
        ));    
 
            


        computed_root.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_root")));

 // hash preimage 
        for (size_t i = 0; i < tree_depth; ++i)
    {
        block_variable<FieldT> inp(pb, authvars.left_digests[i], authvars.right_digests[i], FMT(this->annotation_prefix, " inp_%zu", i));
        sha256_inputs.emplace_back(inp);
        hashers.emplace_back(HashT(pb, 2*sha256_digest_len, inp, (i == 0 ? *computed_root : internal_output[i-1]),
                                   FMT(this->annotation_prefix, " load_hashers_%zu", i)));
    }


     }



    void generate_r1cs_constraints() {
         // Multipacking constraints (for input validation)
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO` sanity check
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");


            
            
           
          
        
            
  
            
            //hash->generate_r1cs_constraints(false); /* ensure correct hash computations */
            
            // Constraint that computed_root * 1 == rootDigest which is equivalent to computed_root == rootDigest
            
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, rootDigest), "Enforce valid proof");
            
            
            
            
        }
          
             

      
      /*         positions.allocate(pb, INCREMENTAL_MERKLE_TREE_DEPTH);


        {
        	 for (size_t i = 0; i < tree_depth; ++i)
    {
        left_digests.emplace_back(digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(annotation_prefix, " left_digests_%zu", i)));
        right_digests.emplace_back(digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(annotation_prefix, " right_digests_%zu", i)));
    }
     authvars.reset(new merkle_authentication_path_variable<FieldT, sha256_gadget>(
            pb, tree_depth, "auth"
        ));
            
        merkle_auth.reset(new merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            tree_depth, //const size_t tree_depth,
            positions, //   const pb_linear_combination_array<FieldT> &address_bits,
            leafDigest, //const digest_variable<FieldT> &leaf_digest,
            rootDigest, //const digest_variable<FieldT> &root_digest,
            *path_s,//   const merkle_authentication_path_variable<FieldT, HashT> &path,
            enforce, //  const pb_linear_combination<FieldT> &read_successful,
            ""     //  const std::string &annotation_prefix);
        ));       
        }
         };

        

authvars->generate_r1cs_constraints();
void generate_r1cs_constraints()
{
    for (size_t i = 0; i < tree_depth; ++i)
    {
        left_digests[i].generate_r1cs_constraints();
        right_digests[i].generate_r1cs_constraints();
    }
}



    

    
}

void generate_r1cs_constraints() {
        for (size_t i = 0; i < INCREMENTAL_MERKLE_TREE_DEPTH; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }

      
        auth->generate_r1cs_constraints();
    }



 void generate_r1cs_witness(const merkle_authentication_path& path) {
 	
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convertVectorToInt(path.index);
        // assert(path.size() == tree_depth);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        path_vars->generate_r1cs_witness(path_index, path.authentication_path);
        ////void generate_r1cs_witness(const size_t address, const merkle_authentication_path &path)
        //path_index is the address

        for (size_t i = 0; i < tree_depth; ++i)
    {
        if (address & (1ul << (tree_depth-1-i)))
        {
            left_digests[i].generate_r1cs_witness(path[i]);
        }
        else
        {
            right_digests[i].generate_r1cs_witness(path[i]);
        }
    }
    
        merkle_auth->generate_r1cs_witness();
    }
};

     merkle_authentication_path get_authentication_path(const size_t address) const;     
            // Allocate space for the verifier input which will be the public inputs, in our case, they are two elements of size 256 each
          /*  
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
            //input_as_bits.insert(input_as_bits.end(), pathDigest.bits.begin(), pathDigest.bits.end());
            
            
            assert(input_as_bits.size() == input_size_in_bits);
            
    
           
            // This gadget will ensure that all of the inputs we provide are boolean constrained.
            
            unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), " unpacker"));
            
            
            
            const size_t currentDirection = 0;
            
            
            currentDirection = directionSelector[0];
            
            pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
            
           // left.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, "left")));
            //right.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, "right")));
            
           // lhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *left, currentDirection, leafDigest, pathDigest, ".lhs"));
           // rhs.reset(new multiplexer_gadget<FieldT>(pb, sha256_digest_len, *right, currentDirection, pathDigest, leafDigest, ".rhs"));
            
            // assert(left.bits.size() == sha256_digest_len);
            //assert(right.bits.size() == sha256_digest_len);
          //  assert(lhs.result().bits.size() == sha256_digest_len);
           // assert(rhs.result().bits.size() == sha256_digest_len);
            
           // block.reset(new block_variable<FieldT>(pb, SHA256_block_size, FMT(this->annotation_prefix, "block")));
            
            
            
            
            
             concatenate block = left || right */
           // block.insert(block.end(), left.bits.begin(), left->bits.end());
           // block.insert(block.end(), right.bits.begin(), right->bits.end());
            //block_variable<FieldT> inp(pb, path.left_digests[i], path.right_digests[i], FMT(this->annotation_prefix, " inp_%zu", i));
            
            
            // Inputs are 256 bit padding and 256 bit message block
            /* h_block.reset(new block_variable<FieldT>(in_pb, {
             block->bits,
             padding_var
             }, "hash_block"));
             
           // assert(block.bits.size() == SHA256_block_size);
            
            
            // Inputs are 256 bit IV and 512 bit h_block (64 bytes)
            // computed_root
            computed_root.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_root")));
            hash.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                      IV,
                                                                      block->bits,
                                                                      *computed_root,
                                                                      FMT(this->annotation_prefix, "computed_root")));

                                                                      
            
            
            assert(computed_root.size() == sha256_digest_len);
            
            
            
            
            
        
        merkle_auth.reset(new merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            tree_depth,
            positions,
            leafDigest,
            rootDigest,
            *path_s,
            enforce,
            ""
        ));
    /*For Merkle tree
       authentication paths, path[0] corresponds to one layer below
       the root (and path[tree_depth-1] corresponds to the layer
       containing the leaf), while address_bits has the reverse order:
       address_bits[0] is LSB, and corresponds to layer containing the
       leaf, and address_bits[tree_depth-1] is MSB, and corresponds to
       the subtree directly under the root. 
                     
       
}
    

    void generate_r1cs_constraints() {

    	// Multipacking constraints (for input validation)
            unpacker.generate_r1cs_constraints(true);
        
        for (size_t i = 0; i < tree_depth; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }
        

        merkle_auth->generate_r1cs_constraints();
        path_vars->generate_r1cs_constraints();


            
            //lhs->generate_r1cs_constraints();
            //rhs->generate_r1cs_constraints();
              // Sanity check
           // generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
            
          //  hash->generate_r1cs_constraints(false); /* ensure correct hash computations 
            
            // Constraint that computed_root * 1 == rootDigest which is equivalent to computed_root == rootDigest
            
          //  this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, rootDigest), "Enforce valid proof");
            
            
   //}

   void generate_r1cs_witness(const MerklePath& path) {
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convertVectorToInt(path.index);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        authvars->generate_r1cs_witness(path_index, path.authentication_path);
        auth->generate_r1cs_witness();
    }
};
    
    
    

    For Merkle tree
       authentication paths, path[0] corresponds to one layer below
       the root (and path[tree_depth-1] corresponds to the layer
       containing the leaf), while address_bits has the reverse order:
       address_bits[0] is LSB, and corresponds to layer containing the
       leaf, and address_bits[tree_depth-1] is MSB, and corresponds to
       the subtree directly under the root. 
                     
                   
            
       */    
            
     
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
     
           // lhs->generate_r1cs_witness();
           // rhs->generate_r1cs_witness();
        
          //  hash->generate_r1cs_witness();
            unpacker->generate_r1cs_witness_from_bits();
            
            
            rootDigest->bits.fill_with_bits(this->pb, root);
            pathDigest0->bits.fill_with_bits(this->pb, digest0);
            
            
            
            
            
        }
    };

 
    
    template<typename FieldT>
    
    // The statement (public values) is called primary input while the witness (the secret values) is called auxiliary input.
    
    const r1cs_primary_input<FieldT> l_input_map (const bit_vector &root, const bit_vector &digest0)
    
    
    
    {
        
        
        
    
     assert(root.bits.size() == sha256_digest_len);
     assert(digest0.bits.size() == sha256_digest_len);
    
    
    
    
        
        
        bit_vector input_as_bits;
        input_as_bits.insert(input_as_bits.end(), root.begin(), root.end());
        input_as_bits.insert(input_as_bits.end(), digest0.begin(), digest0.end());
        
        
        std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;
        
        
        std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
        
        
        std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;
        
        return input_as_field_elements;

      
       } 
    
        
    
    
