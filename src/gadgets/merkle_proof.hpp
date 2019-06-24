#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include<libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include<libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>



using namespace libsnark;
using namespace std;
using namespace libff;



typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
const size_t sha256_digest_len = 256;  


template<typename FieldT>


class merkle_proof_gadget : public gadget<FieldT>
{



public: 

        // Verifier inputs

    	const pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        const pb_variable_array<FieldT> input_as_bits;  // unpacked R1CS input since these values
        shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker;
        const size_t tree_depth; 
        typedef  shared_ptr<sha256_two_to_one_hash_gadget<FieldT>> sha256_gadget;
        std::shared_ptr<merkle_authentication_path_variable<FieldT, sha256_gadget>> authvars; //gadget
        std::shared_ptr<merkle_tree_check_read_gadget<FieldT, sha256_gadget>> merkle_auth;
        std::vector<block_variable<FieldT> > hash_inputs; // the preimages of these hashes (the blocks which should contain left and right inputs)
        std::vector<digest_selector_gadget<FieldT> > digest_selector; // the digest selector gadget
        std::vector<sha256_two_to_one_hash_gadget<FieldT>> hashers; // the sha256 gadgets
        shared_ptr<digest_variable<FieldT> > computed_root; 
        shared_ptr<digest_variable<FieldT>> rootDigest;
       // shared_ptr<digest_variable<FieldT>> pathDigest0;
        shared_ptr<digest_variable<FieldT>> leafDigest;
        shared_ptr<pb_linear_combination_array<FieldT>> directionSelector;
        std::shared_ptr<bit_vector_copy_gadget<FieldT> > check_root; 
        pb_variable_array<FieldT> tree_positions; 
        //pb_linear_combination_array<FieldT> address_bits; 
        //std::vector<digest_variable<FieldT> > internal_output; // the output hash inside the tree
        pb_variable<FieldT> zero; 




        merkle_proof_gadget( protoboard<FieldT>& pb,

            const size_t tree_depth,
            const digest_variable<FieldT> & rootDigest,
        //const digest_variable<FieldT> & pathDigest0,
            const digest_variable<FieldT> & leafDigest,
            const pb_variable<FieldT> & enforce,

            const string &annotation_prefix                           
        //const pb_linear_combination_array<FieldT> & direction_Selector, // const pb_linear_combination<FieldT> &read_successful, // why do we copy gadgets? 
        //const pb_linear_combination_array<FieldT> & directionSelector,              

        //pb_variable_array<FieldT> & tree_positions, // pathDigests


            ) : gadget<FieldT>(pb, "merkle_proof_gadget")

        {

           const size_t input_size_in_bits = sha256_digest_len * 2;
               // input size in fields is 

           {


            const size_t input_size_in_field_elements = libff::div_ceil(input_size_in_bits, FieldT::capacity());

                // we allocate space for the field elements to be of size input_size_in_field_elements
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");

                // finally our input size to size of field elements
                this->pb.set_input_sizes(input_size_in_field_elements); // which should be 4 elements
            }
            
            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
            tree_positions.allocate(pb, tree_depth);
             //assert(tree_depth > 0);
            //assert(tree_depth == tree_positions.size());

            input_as_bits.insert(input_as_bits.end(), rootDigest.bits.begin(), rootDigest.bits.end());
            //input_as_bits.insert(input_as_bits.end(), pathDigest0.bits.begin(), pathDigest0.bits.end());
            
            
            assert(input_as_bits.size() == input_size_in_bits);
            


            
            unpacker.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpacker")));
            


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
            "merkle_auth"     //  const std::string &annotation_prefix);
            )); 



            computed_root.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " computed_root")));



        }


        











        void generate_r1cs_constraints() {



         // Multipacking constraints (for input validation)
            unpacker->generate_r1cs_constraints(true);



            authvars->generate_r1cs_constraints();
            merkle_auth->generate_r1cs_constraints();
              // Sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
            
            
        // Constraint that computed_root * 1 == rootDigest which is equivalent to computed_root == rootDigest
            
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, computed_root, rootDigest), "Enforce valid proof");
            
            
            
            



            
            
            
        }


        void generate_r1cs_witness(const bit_vector &root,
           const bit_vector &leaf,
           size_t path_index,
           const std::vector<std::vector<bool>>& authentication_path
           )
        {


        //size_t path_index = convertVectorToInt(path.index);

        //positions.fill_with_bits_of_ulong(this->pb, path_index);

            authvars->generate_r1cs_witness(path_index, authentication_path);
            merkle_auth->generate_r1cs_witness();

            unpacker->generate_r1cs_witness_from_bits();

        // Fill our digests with our witnessed data
            leafDigest->bits.fill_with_bits(this->pb, leaf);

        // Set the zero pb_variable to zero
            this->pb.val(zero) = FieldT::zero();


            rootDigest->bits.fill_with_bits(this->pb, root);
            tree_positions->bits.fill_with_bits(this->pb, path_index);
            


            
            
        }



    };




    template<typename FieldT>
    

    
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
