#include <utils.hpp>
#include <jubjub/validator.hpp>
#include <jubjub/point.hpp> 
#include <jubjub/params.hpp>
#include <jubjub/scalarmult.hpp>
#include <jubjub/fixed_base_mul.hpp>
#include <jubjub/adder.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <gadgets/field2bits_strict.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include "preimage_proof_gadget.hpp"

using namespace std;
using namespace libff;
using namespace libsnark;
using namespace ethsnarks;
//using ethsnarks::jubjub;

/*Sign:
The signature of a message M under a private key k is the 2*b-bit string ENC(R) || ENC(S). 
 R and S are derived as follows:
- First define r = H(h_b || ... || h_(2b-1) || M) interpreting 2*b-bit strings in little-endian form as integers in {0, 1, ..., 2^(2*b) - 1}.  
- Let R = [r]B and S = (r + H(ENC(R) || ENC(A) || PH(M)) * s) mod
   L.  
   */

    /* Verify

   To verify an edDSA signature ENC(R) || ENC(S) on a message M under
   a public key ENC(A), we proceed as follows:
  - Parse the inputs so that A and R are elements of E, and S is a member of the set {0, 1, ..., L-1}. 
  - Compute h = H(ENC(R) || ENC(A) || M), and check the group
   equation [2^c * S] B = 2^c * R + [2^c * h] A in E.  The signature is
   rejected if parsing fails (including S being out of range) or if the
   group equation does not hold.

   EdDSA verification for a message M is defined as PureEdDSA
   verification for PH(M).
   */

//const size_t sha256_digest_len = 256;
//typedef libff::alt_bn128_pp ppT;
//typedef libff::Fr<ppT> FieldT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;



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

    class eddsa_gadget : public gadget<FieldT> {

    public:
   
    shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker; // do we need a packer as well?
    field2bits_strict ENC_R_x_bits;           // R_x_bits = BITS(R.x) gadget
    field2bits_strict ENC_A_x_bits;           // A_x_bits = BITS(A.x) gadget
    const VariableArrayT RAM_bits;
    shared_ptr<sha256_compression_function_gadget<FieldT>> hash_RAM; // the sha256 gadget hash_RAM = H(R,A,M)
    shared_ptr<digest_variable<FieldT>> msg_hashed; // M = H(m)
    shared_ptr<digest_variable<FieldT>> hash_result;
    ethsnarks::jubjub::PointValidator validator_R; // IsValid(R)
    ethsnarks::jubjub::fixed_base_mul lhs; // lhs = B*s will be of size 2bbits which is 512
    ethsnarks::jubjub::ScalarMult At;  // At= A*hash_RAM  since Base point B has order l so B mod l = 1 which means A mod l= s.B mod l = s which means H(R,A,M)s = H(R,A,M)A M)A
    ethsnarks::jubjub::PointAdder rhs; // rhs = R + (A*hash_RAM)
    // add signature S as input as well
    shared_ptr<block_variable<FieldT>>  block;
    shared_ptr<sha256_compression_function_gadget<FieldT>> hashM; // the sha256 gadget
    pb_variable<FieldT> zero; 
    pb_variable_array<FieldT> padding_var;




    eddsa_gadget(
        protoboard<FieldT> & pb, 
    const ethsnarks::jubjub::Params& in_params, // params a and d from Edward curve
    const ethsnarks::jubjub::EdwardsPoint& in_base,    // B 
    const ethsnarks::jubjub::VariablePointT& in_R,
    const ethsnarks::jubjub::VariablePointT& in_A, 
    const digest_variable<FieldT>& in_msg,
    const VariableArrayT& in_s,     // s
    const std::string& annotation_prefix
    ) :
    gadget<FieldT>(pb, "eddsa_gadget")
    {

    // Convert X & Y coords to bits for hash function
        // An integer 0 < S < L - 1 is encoded in little-endian form as a b-bit string ENC(S).
        ENC_R_x_bits(pb, in_R.x, FMT(this->annotation_prefix, ".R_x_bits")), //256 bits
        //ENC_R_y_bits(pb, in_R.y, FMT(this->annotation_prefix, ".R_x_bits")),
        ENC_A_x_bits(pb, in_A.x, FMT(this->annotation_prefix, ".A_x_bits")), // 256 bits
        //ENC_A_y_bits(pb, in_A.y, FMT(this->annotation_prefix, ".A_x_bits")),


         // IsValid(R) to verify if R is a valid point of the curve
        validator_R(pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R"));

        // lhs = ScalarMult(B, s)
        lhs(pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);




         // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }


        block.reset(new block_variable<FieldT>(pb, {
            in_msg->bits, 
            padding_var
        }, "block"));

        assert(block.bits.size() == SHA256_block_size);






        msg_hashed.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " msg_hashed")));

    // M = H(m)
        hashM.reset(new sha256_compression_function_gadget<FieldT>(pb,
            IV,
            block->bits, //512 bits
            *msg_hashed,
            FMT(this->annotation_prefix, "msg_hashed")));


        RAM_bits(flatten({
            ENC_R_x_bits.result(), //256 bits
            ENC_A_x_bits.result(), //256 bits
            msg_hashed, //256 bits
        })),
        



        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        
        


    // hash_RAM = H(R.x,A.x,M.x)
        hash_result.reset(new digest_variable<FieldT>(pb, sha256_digest_len, FMT(this->annotation_prefix, " hash_result")));

    // hash_RAM = H(R, A, M)
    // hash_RAM = H(R.x,A.x,M.x)

        hash_RAM.reset(new sha256_compression_function_gadget<FieldT>(pb,
            IV,
            RAM_bits,
            *hash_result,
            FMT(this->annotation_prefix, "hash_RAM")));


    // At = ScalarMult(A,hash_RAM)
        At(pb, in_params, in_A.x, in_A.y, hash_RAM, FMT(this->annotation_prefix, ".At = A * hash_RAM")),

    // rhs = PointAdd(R, At)
        rhs(pb, in_params, in_R.x, in_R.y, At.result_x(), At.result_y(), FMT(this->annotation_prefix, ".rhs"));
        
 // The PureEdDSA signature of a message M under a private key k is the 2*b-bit string ENC(R) || ENC(S) which means 512 bits 

    }

    void generate_r1cs_constraints()
    {
        ENC_R_x_bits.generate_r1cs_constraints();
        ENC_A_x_bits.generate_r1cs_constraints();
        validator_R.generate_r1cs_constraints();
        lhs.generate_r1cs_constraints();
        hashM.generate_r1cs_constraints();
        hash_RAM.generate_r1cs_constraints();
        At.generate_r1cs_constraints();
        rhs.generate_r1cs_constraints();

    //Signature verification

    // Verify the two points are equal which means [2^c * S] B = 2^c * R + [2^c * h] A

       // lhs == rhs <=> ScalarMult(B, s)= R +  ScalarMult(A,hash_RAM)
        this->pb.add_r1cs_constraint(
            ConstraintT(lhs.result_x(), FieldT::one(), rhs.result_x()),
            FMT(this->annotation_prefix, "lhs.x == rhs.x"));

        this->pb.add_r1cs_constraint(
            ConstraintT(lhs.result_y(), FieldT::one(), rhs.result_y()),
            FMT(this->annotation_prefix, "lhs.y == rhs.y"));
    }


    void generate_r1cs_witness()
    {
        ENC_R_x_bits.generate_r1cs_witness();
        ENC_A_x_bits.generate_r1cs_witness();
        validator_R.generate_r1cs_witness();
        lhs.generate_r1cs_witness();
        hashM.generate_r1cs_witness();
        hash_RAM.generate_r1cs_witness();
        At.generate_r1cs_witness();
        rhs.generate_r1cs_witness();
    }




};